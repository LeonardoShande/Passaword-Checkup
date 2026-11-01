#!/usr/bin/env node
'use strict';

/**
 * Verificador de paquetes (Node puro).
 *
 *   node scripts/verify.js dist/password-checkup-v1.3.0.zip
 *
 * Comprueba, SIN extraer nada a disco:
 *   - estructura del zip coherente (directorio central, cabeceras locales, comentarios);
 *   - rutas seguras: sin «..», sin rutas absolutas ni de Windows, sin NUL, sin duplicados,
 *     todo bajo una única carpeta raíz (defensa contra «zip slip»);
 *   - sin enlaces simbólicos ni entradas cifradas;
 *   - límites de tamaño y cantidad (defensa contra «zip bombs»);
 *   - CRC-32 de cada archivo;
 *   - que SHA256SUMS cubra exactamente los archivos del zip y que cada hash coincida;
 *   - si existe <zip>.sha256 al lado, que el hash del zip coincida.
 */

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');

const MAX_ENTRIES = 1000;
const MAX_TOTAL_BYTES = 50 * 1024 * 1024;
const MAX_ENTRY_BYTES = 10 * 1024 * 1024;

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

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

function unsafeName(name) {
  if (!name || name.includes('\0') || name.includes('\\')) return 'caracteres no permitidos';
  if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) return 'ruta absoluta';
  if (name.split('/').some((seg) => seg === '..' || seg === '.')) return 'segmento «..» o «.»';
  if (name.endsWith('/')) return 'entrada de directorio inesperada';
  return null;
}

function verifyZip(zipPath) {
  const problems = [];
  const fail = (msg) => problems.push(msg);
  const result = () => ({ ok: problems.length === 0, problems, files: [] });

  let buf;
  try { buf = fs.readFileSync(zipPath); } catch (e) { fail(`No se puede leer el archivo: ${e.message}`); return result(); }

  // --- EOCD
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) { fail('No es un zip válido (falta el directorio final).'); return result(); }
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  const commentLen = buf.readUInt16LE(eocd + 20);
  if (eocd + 22 + commentLen !== buf.length) fail('Hay datos extra después del final del zip.');
  if (count > MAX_ENTRIES) { fail(`Demasiadas entradas (${count}).`); return result(); }
  if (cdOffset + cdSize > eocd) { fail('Directorio central fuera de rango.'); return result(); }

  // --- entradas
  const entries = [];
  const seen = new Set();
  let total = 0;
  let pos = cdOffset;
  for (let n = 0; n < count; n++) {
    if (pos + 46 > buf.length || buf.readUInt32LE(pos) !== 0x02014b50) { fail('Directorio central dañado.'); return result(); }
    const flags = buf.readUInt16LE(pos + 8);
    const method = buf.readUInt16LE(pos + 10);
    const crc = buf.readUInt32LE(pos + 16);
    const csize = buf.readUInt32LE(pos + 20);
    const usize = buf.readUInt32LE(pos + 24);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const cmtLen = buf.readUInt16LE(pos + 32);
    const ext = buf.readUInt32LE(pos + 38) >>> 0;
    const lho = buf.readUInt32LE(pos + 42);
    const name = buf.toString('utf8', pos + 46, pos + 46 + nameLen);
    pos += 46 + nameLen + extraLen + cmtLen;

    const bad = unsafeName(name);
    if (bad) fail(`Ruta insegura «${name}»: ${bad}.`);
    if (seen.has(name)) fail(`Entrada duplicada: ${name}`);
    seen.add(name);
    if (flags & 1) fail(`Entrada cifrada no admitida: ${name}`);
    if (((ext >>> 16) & 0o170000) === 0o120000) fail(`Enlace simbólico no permitido: ${name}`);
    if (method !== 0 && method !== 8) fail(`Método de compresión no admitido (${method}): ${name}`);
    if (usize > MAX_ENTRY_BYTES) fail(`Entrada demasiado grande: ${name}`);
    total += usize;
    if (total > MAX_TOTAL_BYTES) { fail('Tamaño total descomprimido excesivo (posible zip bomb).'); return result(); }

    // cabecera local
    if (lho + 30 > buf.length || buf.readUInt32LE(lho) !== 0x04034b50) { fail(`Cabecera local dañada: ${name}`); continue; }
    const lName = buf.toString('utf8', lho + 30, lho + 30 + buf.readUInt16LE(lho + 26));
    if (lName !== name) fail(`El nombre local no coincide con el del directorio: ${name}`);
    const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    if (start + csize > cdOffset) { fail(`Datos fuera de rango: ${name}`); continue; }
    let data = buf.subarray(start, start + csize);
    if (method === 8) {
      try { data = zlib.inflateRawSync(data, { maxOutputLength: MAX_ENTRY_BYTES }); } catch { fail(`No se pudo descomprimir: ${name}`); continue; }
    }
    if (data.length !== usize) fail(`Tamaño incorrecto: ${name}`);
    if (crc32(data) !== crc) fail(`CRC-32 incorrecto (archivo alterado o dañado): ${name}`);
    entries.push({ name, data });
  }

  // --- una única carpeta raíz
  const roots = new Set(entries.map((e) => e.name.split('/')[0]));
  if (roots.size !== 1) fail('El zip debe tener una única carpeta raíz.');
  const rootDir = [...roots][0];
  if (entries.some((e) => !e.name.includes('/'))) fail('Hay archivos fuera de la carpeta raíz.');

  // --- SHA256SUMS
  const sumsEntry = entries.find((e) => e.name === `${rootDir}/SHA256SUMS`);
  if (!sumsEntry) fail('Falta SHA256SUMS dentro del zip.');
  else {
    const listed = new Map();
    for (const line of sumsEntry.data.toString('utf8').split('\n')) {
      if (!line.trim()) continue;
      const m = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
      if (!m) { fail(`Línea inválida en SHA256SUMS: ${line.slice(0, 60)}`); continue; }
      if (unsafeName(m[2])) fail(`Ruta insegura en SHA256SUMS: ${m[2]}`);
      listed.set(m[2], m[1]);
    }
    const actual = new Map(entries.filter((e) => e !== sumsEntry).map((e) => [e.name.slice(rootDir.length + 1), e]));
    for (const [rel, entry] of actual) {
      if (!listed.has(rel)) fail(`Archivo no cubierto por SHA256SUMS: ${rel}`);
      else if (listed.get(rel) !== sha256(entry.data)) fail(`SHA-256 distinto (alterado): ${rel}`);
    }
    for (const rel of listed.keys()) if (!actual.has(rel)) fail(`SHA256SUMS lista un archivo que no está en el zip: ${rel}`);
  }

  // --- hash externo
  const shaFile = `${zipPath}.sha256`;
  if (fs.existsSync(shaFile)) {
    const expected = fs.readFileSync(shaFile, 'utf8').trim().split(/\s+/)[0];
    if (expected !== sha256(buf)) fail('El SHA-256 del zip no coincide con el archivo .sha256.');
  }

  return { ok: problems.length === 0, problems, files: entries.map((e) => e.name) };
}

if (require.main === module) {
  const target = process.argv[2];
  if (!target) {
    console.error('Uso: node scripts/verify.js <archivo.zip>');
    process.exit(2);
  }
  const r = verifyZip(path.resolve(target));
  if (r.ok) {
    console.log(`OK  ${r.files.length} archivos verificados (rutas, CRC-32 y SHA-256).`);
  } else {
    console.error('FALLO de verificación:');
    for (const p of r.problems) console.error('  - ' + p);
    process.exit(1);
  }
}

module.exports = { verifyZip, crc32, unsafeName };
