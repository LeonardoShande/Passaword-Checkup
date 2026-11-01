'use strict';

/**
 * Backend de Check-up de contraseñas — Node puro, cero dependencias.
 *
 * Qué hace:
 *   - Sirve el frontend estático (public/) y los módulos compartidos (/shared/*.js: puntaje, ataques, URL).
 *   - GET /api/content        -> contenido educativo (tarjetas "Más info").
 *   - GET /api/demo/session   -> envía 2 cookies de DEMO (una protegida, otra descuidada).
 *   - GET /api/demo/logs      -> muestra al visitante SUS propias entradas del registro.
 *   - GET /api/health         -> comprobación de estado.
 *
 * Decisiones de seguridad (ver README):
 *   - La contraseña NUNCA llega al servidor: el análisis ocurre en el navegador.
 *     Por eso no existe un endpoint /api/analyze.
 *   - Cabeceras de seguridad + CSP estricta (sin scripts ni estilos inline).
 *   - Registro mínimo: método, ruta SIN query string, estado, duración, IP anonimizada.
 *   - Límite de peticiones por IP en /api/*.
 */

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const content = require('./src/content');

const PUBLIC_DIR = path.join(__dirname, 'public');
// Únicos archivos de src/ que se exponen al navegador (lista blanca explícita).
const SHARED_FILES = {
  '/shared/scoring.js': path.join(__dirname, 'src', 'scoring.js'),
  '/shared/attacks.js': path.join(__dirname, 'src', 'attacks.js'),
  '/shared/urlcheck.js': path.join(__dirname, 'src', 'urlcheck.js'),
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

// connect-src admite solo api.pwnedpasswords.com para la comprobación opcional de filtraciones.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' https://api.pwnedpasswords.com",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join('; ');

const SECURITY_HEADERS = {
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

const COOKIE_FLAGS = [
  { flag: 'HttpOnly', meaning: 'JavaScript no puede leer la cookie (frena el robo por XSS).' },
  { flag: 'Secure', meaning: 'Solo se envía por HTTPS (frena el espionaje en la red).' },
  { flag: 'SameSite=Strict', meaning: 'No se envía en peticiones que vienen de otros sitios (frena CSRF).' },
  { flag: 'Max-Age', meaning: 'Caduca pronto: una cookie robada deja de servir antes.' },
  { flag: 'Path=/', meaning: 'Alcance de la cookie dentro del sitio.' },
];

function createApp(options = {}) {
  const {
    trustProxy = false, // true solo si estás detrás de un proxy de confianza (Nginx, Render…)
    rateMax = 60,
    rateWindowMs = 60_000,
    logLimit = 500,
  } = options;

  const salt = crypto.randomBytes(16).toString('hex'); // cambia en cada arranque
  const logs = [];
  const buckets = new Map();

  const anonymize = (ip) => crypto.createHash('sha256').update(salt + ip).digest('hex').slice(0, 8);

  function clientIp(req) {
    if (trustProxy) {
      const xff = req.headers['x-forwarded-for'];
      if (typeof xff === 'string' && xff) return xff.split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
  }

  const isHttps = (req) =>
    Boolean(req.socket.encrypted) || (trustProxy && req.headers['x-forwarded-proto'] === 'https');

  // Devuelve 0 si la petición pasa, o los segundos a esperar si está limitada.
  function rateLimit(key, now) {
    const bucket = buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + rateWindowMs });
      if (buckets.size > 5000) for (const [k, b] of buckets) if (now >= b.resetAt) buckets.delete(k);
      return 0;
    }
    bucket.count += 1;
    return bucket.count > rateMax ? Math.ceil((bucket.resetAt - now) / 1000) : 0;
  }

  function respond(req, res, status, type, body, headers = {}) {
    res.statusCode = status;
    res.setHeader('Content-Type', type);
    res.setHeader('Content-Length', Buffer.byteLength(body));
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.end(req.method === 'HEAD' ? undefined : body);
  }

  const sendJson = (req, res, status, data) =>
    respond(req, res, status, MIME['.json'], JSON.stringify(data), { 'Cache-Control': 'no-store' });

  const sendText = (req, res, status, text) =>
    respond(req, res, status, MIME['.txt'], text, { 'Cache-Control': 'no-store' });

  async function sendFile(req, res, file) {
    let data;
    try {
      data = await fs.readFile(file);
    } catch {
      return sendText(req, res, 404, 'No encontrado');
    }
    const type = MIME[path.extname(file)] || 'application/octet-stream';
    res.statusCode = 200;
    res.setHeader('Content-Type', type);
    res.setHeader('Content-Length', data.length);
    res.setHeader('Cache-Control', 'no-cache');
    res.end(req.method === 'HEAD' ? undefined : data);
  }

  function serveStatic(req, res, pathname) {
    let rel;
    try {
      rel = decodeURIComponent(pathname);
    } catch {
      return sendText(req, res, 400, 'Solicitud inválida');
    }
    if (rel.includes('\0')) return sendText(req, res, 400, 'Solicitud inválida');
    if (rel.endsWith('/')) rel += 'index.html';
    if (rel.split('/').some((seg) => seg.startsWith('.'))) return sendText(req, res, 404, 'No encontrado');

    const file = path.join(PUBLIC_DIR, path.normalize(rel));
    if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) {
      return sendText(req, res, 403, 'Prohibido');
    }
    return sendFile(req, res, file);
  }

  // Demo educativa: NO autentica nada, solo muestra cómo se ven las cookies y sus atributos.
  function demoSession(req, res) {
    const sid = crypto.randomBytes(16).toString('hex');
    const secure = isHttps(req) ? '; Secure' : '';
    const protectedCookie = `demo_sid=${sid}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict${secure}`;
    const carelessCookie = 'demo_prefs=tema%3Doscuro; Path=/; Max-Age=600';
    res.setHeader('Set-Cookie', [protectedCookie, carelessCookie]);

    sendJson(req, res, 200, {
      cookies: [
        {
          name: 'demo_sid',
          // El valor real no se repite aquí: una cookie HttpOnly no es legible desde JavaScript.
          header: `demo_sid=${sid.slice(0, 6)}…(oculto); Path=/; Max-Age=600; HttpOnly; SameSite=Strict${secure}`,
          protected: true,
          note: 'Cookie «de sesión» bien configurada. Un script malicioso NO puede leerla.',
        },
        {
          name: 'demo_prefs',
          header: carelessCookie,
          protected: false,
          note: 'Cookie descuidada (sin HttpOnly). Cualquier script de la página puede leerla.',
        },
      ],
      flags: COOKIE_FLAGS,
      secureApplied: Boolean(secure),
      note: secure
        ? 'La conexión es HTTPS, así que se añadió Secure.'
        : 'Estás en HTTP (probablemente localhost): en producción añadiría también Secure.',
    });
  }

  async function handle(req, res) {
    const started = process.hrtime.bigint();
    const who = anonymize(clientIp(req));
    let loggedPath = '-';

    res.on('finish', () => {
      logs.push({
        time: new Date().toISOString(),
        method: req.method,
        path: loggedPath, // solo el pathname: jamás la query string
        status: res.statusCode,
        ms: Math.round(Number(process.hrtime.bigint() - started) / 1e5) / 10,
        ip: who,
        ua: String(req.headers['user-agent'] || '').slice(0, 80),
      });
      if (logs.length > logLimit) logs.shift();
    });

    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    // HSTS solo tiene sentido (y solo se honra) sobre HTTPS.
    if (isHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    if (!req.url || !req.url.startsWith('/') || req.url.startsWith('//')) {
      return sendText(req, res, 400, 'Solicitud inválida');
    }
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      return sendText(req, res, 400, 'Solicitud inválida');
    }
    const { pathname } = url;
    loggedPath = pathname.slice(0, 120);

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.setHeader('Allow', 'GET, HEAD');
      return sendText(req, res, 405, 'Método no permitido');
    }

    if (pathname.startsWith('/api/')) {
      const retry = rateLimit(who, Date.now());
      if (retry) {
        res.setHeader('Retry-After', String(retry));
        return sendJson(req, res, 429, { error: 'Demasiadas solicitudes. Intenta de nuevo en unos segundos.' });
      }
    }

    switch (pathname) {
      case '/api/health':
        return sendJson(req, res, 200, { status: 'ok' });
      case '/api/content':
        return sendJson(req, res, 200, content);
      case '/api/demo/session':
        return demoSession(req, res);
      case '/api/demo/logs':
        return sendJson(req, res, 200, {
          note: 'Solo ves tus propias entradas (IP anonimizada). Observa que no hay contraseñas ni parámetros de URL.',
          entries: logs.filter((l) => l.ip === who).slice(-12).reverse(),
        });
      default:
        if (Object.prototype.hasOwnProperty.call(SHARED_FILES, pathname)) {
          return sendFile(req, res, SHARED_FILES[pathname]);
        }
        if (pathname.startsWith('/api/')) return sendJson(req, res, 404, { error: 'Ruta de API no encontrada' });
        return serveStatic(req, res, pathname);
    }
  }

  return http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      console.error('Error interno:', err.message); // nunca registramos cuerpos ni cabeceras
      if (!res.headersSent) sendText(req, res, 500, 'Error interno');
      else res.end();
    });
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1'; // en contenedores/hosting usa HOST=0.0.0.0
  const server = createApp({ trustProxy: process.env.TRUST_PROXY === '1' });
  server.listen(port, host, () => console.log(`Check-up de contraseñas en http://${host}:${port}`));
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => server.close(() => process.exit(0)));
  }
}

module.exports = { createApp, CSP };
