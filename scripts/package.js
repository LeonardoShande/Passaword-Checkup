#!/usr/bin/env node
'use strict';

/**
 * Empaquetador seguro y REPRODUCIBLE (Node puro, sin dependencias).
 *
 *   npm run package          ->  dist/password-checkup-vX.Y.Z.zip  (+ .sha256)
 *
 * Qué hace para que el zip sea de confianza:
 *   1. Lista blanca de contenido: solo archivos regulares; sin node_modules, .git, dist, .env,
 *      archivos ocultos (salvo .github y .gitignore) ni enlaces simbólicos (falla si los hay).
 *   2. Escaneo de secretos (claves privadas, tokens) y de rutas locales: si algo aparece, aborta.
 *   3. Reproducible: orden alfabético, fecha fija (SOURCE_DATE_EPOCH), permisos 0644 y método
 *      «stored» (sin compresión) => mismo contenido = mismo zip, bit a bit, en cualquier máquina.
 *      Así cualquiera puede reconstruirlo y comparar el hash.
 *   4. Integridad: SHA256SUMS (todos los archivos) + MANIFEST.txt (resumen legible) dentro del
 *      zip, y <zip>.sha256 al lado. El comentario del zip (visible con `unzip -z`) lleva el banner.
 *   5. Se autoverifica con scripts/verify.js antes de terminar.
 *
 * Importante: esto da INTEGRIDAD y procedencia, no confidencialidad. Si necesitas cifrarlo,
 * hazlo aparte (por ejemplo con `age` o 7-Zip AES-256) y comparte la clave por otro canal.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { BANNER, box } = require('./banner');

const ROOT = path.resolve(__dirname, '..');
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git']);
const ALLOW_DOT = new Set(['.github', '.gitignore']);
const GENERATED = new Set(['MANIFEST.txt', 'SHA256SUMS']);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const DEFAULT_EPOCH = 1767225600; // 2026-01-01T00:00:00Z

// Se construyen por partes para que este archivo no se marque a sí mismo.
const LOCAL_PATH_MARKERS = ['/ho' + 'me/claude', '/tm' + 'p/claude', 'C:\\Us' + 'ers\\'];
const SECRET_PATTERNS = [
  ['clave privada', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/],
  ['clave de AWS', /\bAKIA[0-9A-Z]{16}\b/],
  ['token de GitHub', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/],
  ['token de GitHub (fine-grained)', /\bgithub_pat_[A-Za-z0-9_]{50,}\b/],
  ['token de Slack', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['clave de API de Google', /\bAIza[0-9A-Za-z_-]{35}\b/],
];

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const byteCompare = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));

// ---------------------------------------------------------------- recopilar archivos
function collect(root = ROOT) {
  const files = [];
  const skipped = [];
  (function walk(dir, rel) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (SKIP_DIRS.has(entry.name)) continue;
      // Archivos que el propio empaquetador genera: si ya existen (zip extraído y vuelto a
      // empaquetar) se ignoran y se regeneran, para que el resultado sea idéntico.
      if (!rel && GENERATED.has(entry.name)) continue;
      if (entry.name.startsWith('.') && !ALLOW_DOT.has(entry.name)) { skipped.push(relPath); continue; }
      if (entry.isSymbolicLink()) throw new Error(`Enlace simbólico no permitido en el paquete: ${relPath}`);
      if (entry.isDirectory()) walk(path.join(dir, entry.name), relPath);
      else if (entry.isFile()) {
        if (/\.(log|zip|sha256|tmp|swp)$/i.test(entry.name)) { skipped.push(relPath); continue; }
        const full = path.join(dir, entry.name);
        const size = fs.statSync(full).size;
        if (size > MAX_FILE_BYTES) throw new Error(`Archivo demasiado grande (${size} bytes): ${relPath}`);
        files.push({ name: relPath, data: fs.readFileSync(full) });
      } else throw new Error(`Tipo de archivo no permitido: ${relPath}`);
    }
  })(root, '');
  files.sort((a, b) => byteCompare(a.name, b.name));
  return { files, skipped };
}

// ---------------------------------------------------------------- escaneo de secretos
function scanForSecrets(files) {
  const findings = [];
  for (const f of files) {
    if (f.data.includes(0)) continue; // binario
    const text = f.data.toString('utf8');
    for (const [label, re] of SECRET_PATTERNS) if (re.test(text)) findings.push({ file: f.name, problem: label });
    for (const marker of LOCAL_PATH_MARKERS) if (text.includes(marker)) findings.push({ file: f.name, problem: `ruta local («${marker}»)` });
  }
  return findings;
}

// ---------------------------------------------------------------- escritor de zip (stored)
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dosDateTime(epoch) {
  const d = new Date(epoch * 1000);
  const year = Math.max(d.getUTCFullYear(), 1980);
  return {
    time: (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >> 1),
    date: ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate(),
  };
}

/** entries: [{ name, data: Buffer }] -> Buffer del zip. `comment` debe ser ASCII. */
function buildZip(entries, { epoch = DEFAULT_EPOCH, comment = '' } = {}) {
  if (/[^\x20-\x7e\r\n]/.test(comment)) throw new Error('El comentario del zip debe ser ASCII.');
  const { time, date } = dosDateTime(epoch);
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const crc = crc32(e.data);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4); // versión necesaria
    lh.writeUInt16LE(0x0800, 6); // nombres UTF-8, sin cifrado
    lh.writeUInt16LE(0, 8); // método 0 = stored
    lh.writeUInt16LE(time, 10);
    lh.writeUInt16LE(date, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(e.data.length, 18);
    lh.writeUInt32LE(e.data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE((3 << 8) | 20, 4); // creado en Unix
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(time, 12);
    ch.writeUInt16LE(date, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(e.data.length, 20);
    ch.writeUInt32LE(e.data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(((0o100644 << 16) >>> 0), 38); // archivo regular, permisos 0644
    ch.writeUInt32LE(offset, 42);

    locals.push(lh, name, e.data);
    centrals.push(ch, name);
    offset += lh.length + name.length + e.data.length;
  }

  const cd = Buffer.concat(centrals);
  const zipComment = Buffer.from(comment, 'ascii');
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(zipComment.length, 20);
  return Buffer.concat([...locals, cd, end, zipComment]);
}

// ---------------------------------------------------------------- manifiesto legible
function manifestText({ name, version, files, epoch }) {
  const total = files.reduce((n, f) => n + f.data.length, 0);
  const W = 76;
  const header = box([
    `${name.toUpperCase()}  ::  paquete v${version}`,
    '',
    `Generado ........ ${new Date(epoch * 1000).toISOString()} (fecha fija: reproducible)`,
    `Archivos ........ ${files.length}`,
    `Tamano total .... ${total} bytes`,
    'Formato ......... zip "stored", permisos 0644, sin archivos ocultos',
  ], W, '+', '=');

  const rows = files.map((f) =>
    `  ${String(f.data.length).padStart(7)}  ${sha256(f.data).slice(0, 16)}  ${f.name}`);

  const how = box([
    'COMO VERIFICAR LA INTEGRIDAD',
    '',
    `1) sha256sum -c ${name}-v${version}.zip.sha256     (junto al .zip)`,
    '2) unzip el .zip, entra a la carpeta y ejecuta:',
    '       sha256sum -c SHA256SUMS',
    '3) o bien:  node scripts/verify.js <archivo.zip>',
    '',
    'Si algun archivo no coincide, NO ejecutes el contenido.',
    'Reconstruir:  npm run package   (mismo contenido = mismo hash)',
  ], W);

  return [BANNER, '', header, '', '     BYTES  SHA-256 (16)       RUTA', '  --------  ----------------  ----------------------------', ...rows, '', how, ''].join('\n');
}

// ---------------------------------------------------------------- construir
function build({ root = ROOT, outDir, epoch } = {}) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const name = pkg.name;
  const version = pkg.version;
  const when = Number(epoch || process.env.SOURCE_DATE_EPOCH || DEFAULT_EPOCH);
  const out = path.resolve(outDir || process.env.OUT_DIR || path.join(root, 'dist'));

  const { files, skipped } = collect(root);
  const findings = scanForSecrets(files);
  if (findings.length) {
    const lines = findings.map((f) => `  - ${f.file}: ${f.problem}`).join('\n');
    throw new Error(`Se detectaron posibles secretos o rutas locales; no se genera el paquete:\n${lines}`);
  }

  const manifest = { name: 'MANIFEST.txt', data: Buffer.from(manifestText({ name, version, files, epoch: when }), 'utf8') };
  const withManifest = [...files, manifest];
  const sums = {
    name: 'SHA256SUMS',
    data: Buffer.from(withManifest.map((f) => `${sha256(f.data)}  ${f.name}`).join('\n') + '\n', 'utf8'),
  };
  const all = [...withManifest, sums].sort((a, b) => byteCompare(a.name, b.name));
  const prefix = `${name}/`;

  const comment = [
    'SECURITY TECH :: ' + name + ' v' + version,
    '------------------------------------------------------------',
    'Integridad : sha256sum -c SHA256SUMS   (dentro de la carpeta)',
    'Zip        : sha256sum -c ' + name + '-v' + version + '.zip.sha256',
    'Reconstruir: npm run package  (build reproducible)',
    'Aviso      : esto da integridad, no cifrado.',
  ].join('\n');

  const zip = buildZip(all.map((f) => ({ name: prefix + f.name, data: f.data })), { epoch: when, comment });
  fs.mkdirSync(out, { recursive: true });
  const zipName = `${name}-v${version}.zip`;
  const zipPath = path.join(out, zipName);
  const digest = sha256(zip);
  fs.writeFileSync(zipPath, zip, { mode: 0o644 });
  fs.writeFileSync(`${zipPath}.sha256`, `${digest}  ${zipName}\n`, { mode: 0o644 });

  return { zipPath, shaPath: `${zipPath}.sha256`, digest, files: all.length, bytes: zip.length, skipped, name, version };
}

if (require.main === module) {
  try {
    const r = build();
    const { verifyZip } = require('./verify');
    const check = verifyZip(r.zipPath);
    if (!check.ok) throw new Error('Autoverificación fallida:\n  - ' + check.problems.join('\n  - '));
    console.log(BANNER + '\n');
    console.log(box([
      `${r.name} v${r.version}  ::  paquete listo`,
      '',
      `Archivos ... ${r.files}   (omitidos: ${r.skipped.length ? r.skipped.join(', ') : 'ninguno'})`,
      `Tamano ..... ${r.bytes} bytes`,
      `SHA-256 .... ${r.digest}`,
      `Zip ........ ${path.relative(process.cwd(), r.zipPath)}`,
      'Autoverificacion ... OK (rutas seguras, CRC y SHA256SUMS)',
    ], 90, '+', '='));
  } catch (err) {
    console.error('\nERROR: ' + err.message);
    process.exit(1);
  }
}

module.exports = { build, buildZip, collect, scanForSecrets, crc32, sha256, DEFAULT_EPOCH };
