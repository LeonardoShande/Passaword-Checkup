/*!
 * urlcheck.js — analizador didáctico de direcciones (URL), sin red y sin dependencias.
 *
 * Responde: "¿esta dirección tiene señales de ser una página falsa o insegura
 * antes de escribir mi contraseña?"  Todo ocurre en el navegador: NUNCA se conecta a la URL.
 *
 * Es una heurística: sin señales de alerta NO significa que el sitio sea legítimo.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.UrlCheck = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const MAX_LENGTH = 2048;

  // marca -> dominios oficiales (dominio registrable)
  const BRANDS = {
    google: ['google.com', 'google.com.pe', 'gmail.com', 'youtube.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com'],
    microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'],
    apple: ['apple.com', 'icloud.com'],
    amazon: ['amazon.com', 'amazon.es', 'amazon.com.mx', 'amazon.com.br'],
    facebook: ['facebook.com', 'fb.com'],
    instagram: ['instagram.com'],
    whatsapp: ['whatsapp.com', 'whatsapp.net'],
    paypal: ['paypal.com'],
    netflix: ['netflix.com'],
    github: ['github.com', 'github.io', 'githubusercontent.com'],
    binance: ['binance.com'],
    telegram: ['telegram.org', 't.me'],
    linkedin: ['linkedin.com'],
    dropbox: ['dropbox.com'],
    mercadolibre: ['mercadolibre.com', 'mercadolibre.com.pe', 'mercadolibre.com.ar', 'mercadolibre.com.mx', 'mercadopago.com'],
    bbva: ['bbva.com', 'bbva.pe', 'bbva.es', 'bbva.mx', 'bbva.com.pe'],
    viabcp: ['viabcp.com', 'bcp.com.pe'],
    interbank: ['interbank.pe'],
    scotiabank: ['scotiabank.com', 'scotiabank.com.pe'],
    santander: ['santander.com', 'santander.com.mx', 'santander.cl'],
  };

  // Sufijos de dos niveles frecuentes (aproximación al Public Suffix List)
  const TWO_LEVEL = new Set([
    'co.uk', 'org.uk', 'com.pe', 'gob.pe', 'edu.pe', 'org.pe', 'com.ar', 'com.mx', 'com.br',
    'com.co', 'com.ec', 'com.bo', 'com.uy', 'com.ve', 'com.au', 'co.jp', 'com.es', 'co.nz',
  ]);

  const RISKY_TLDS = new Set([
    'zip', 'mov', 'top', 'xyz', 'click', 'work', 'loan', 'country', 'gq', 'tk', 'ml', 'cf', 'ga',
    'icu', 'rest', 'cam', 'monster', 'buzz', 'support', 'kim', 'men',
  ]);

  const SHORTENERS = new Set([
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'is.gd', 'ow.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'buff.ly', 'tiny.cc',
  ]);

  const LURE_WORDS = ['login', 'signin', 'secure', 'seguro', 'verify', 'verifica', 'verificar', 'account', 'cuenta',
    'update', 'actualiza', 'wallet', 'support', 'soporte', 'billing', 'recover', 'recupera', 'password', 'clave'];

  const SENSITIVE_PARAMS = ['password', 'passwd', 'pass', 'pwd', 'clave', 'contrasena', 'contraseña', 'secret',
    'token', 'otp', 'pin', 'apikey', 'api_key', 'session', 'sessionid', 'sid'];

  const LEET = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b' };

  function levenshtein(a, b) {
    if (a === b) return 0;
    const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      let diag = prev[0];
      prev[0] = i;
      for (let j = 1; j <= b.length; j++) {
        const tmp = prev[j];
        prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
        diag = tmp;
      }
    }
    return prev[b.length];
  }

  function registrableDomain(host) {
    const labels = host.split('.');
    if (labels.length <= 2) return host;
    const last2 = labels.slice(-2).join('.');
    return TWO_LEVEL.has(last2) ? labels.slice(-3).join('.') : last2;
  }

  const isIPv4 = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
  const isPrivateIPv4 = (h) => /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h);

  function deLeet(text) {
    return text.replace(/[0134578]/g, (c) => LEET[c] || c).replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  function parse(input) {
    let text = String(input == null ? '' : input).trim();
    if (!text) return { error: 'Escribe o pega una dirección para analizar.' };
    if (text.length > MAX_LENGTH) return { error: 'La dirección es demasiado larga para analizarla.' };
    if (/\s/.test(text)) return { error: 'Una dirección web no lleva espacios. Revisa lo que pegaste.' };

    let assumedScheme = false;
    if (!/^[a-z][a-z0-9+.-]*:/i.test(text) || /^[^/]+:\d+(\/|$)/.test(text)) {
      text = 'https://' + text;
      assumedScheme = true;
    }
    try {
      return { url: new URL(text), assumedScheme };
    } catch {
      return { error: 'No parece una dirección válida. Ejemplo: https://www.ejemplo.com/inicio' };
    }
  }

  function analyze(input) {
    const parsed = parse(input);
    if (parsed.error) return { ok: false, error: parsed.error };
    const { url, assumedScheme } = parsed;
    const checks = [];
    const add = (level, id, title, detail) => checks.push({ level, id, title, detail });

    // --- esquema ---
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      add('bad', 'scheme', 'No es una página web normal',
        `El esquema «${url.protocol}» no es http ni https. Los enlaces así se usan para ejecutar código o abrir archivos: no lo abras.`);
      return finish(url, checks, '');
    }

    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    const labels = host.split('.');
    const bracketed = host.startsWith('[');
    const domain = bracketed || isIPv4(host) ? host : registrableDomain(host);

    if (url.protocol === 'http:') {
      add('bad', 'https', 'No usa HTTPS',
        'Lo que escribas viaja sin cifrar: cualquiera en la red (Wi-Fi pública, proveedor) podría leer tu contraseña. No la escribas aquí.');
    } else if (assumedScheme) {
      add('info', 'https', 'Sin protocolo: asumimos https',
        'Pegaste la dirección sin «https://». Confirma en tu navegador que realmente se abre con HTTPS.');
    } else {
      add('ok', 'https', 'Usa HTTPS', 'La conexión va cifrada. Ojo: eso no prueba que el sitio sea honesto, también las páginas falsas lo usan.');
    }

    // --- usuario@ en la dirección ---
    if (url.username || url.password) {
      add('bad', 'userinfo', 'Truco de la arroba (@)',
        `Lo que va antes de la @ es solo un «usuario» inventado. La dirección realmente te lleva a «${host}».`);
    }

    // --- IP en vez de nombre ---
    if (bracketed || isIPv4(host)) {
      if (isPrivateIPv4(host)) {
        add('info', 'ip', 'Dirección de red local', 'Es un equipo de tu propia red o de tu computadora (normal al desarrollar, raro para un servicio real).');
      } else {
        add('bad', 'ip', 'Usa una dirección IP, no un nombre',
          'Los servicios legítimos usan nombres de dominio. Las páginas de phishing usan IP para evitar bloqueos.');
      }
    }

    // --- dominios internacionales (homógrafos) ---
    if (labels.some((l) => l.startsWith('xn--'))) {
      add('warn', 'punycode', 'Dominio con caracteres internacionales',
        'Algunas letras de otros alfabetos se ven idénticas a las latinas (la «а» cirílica y la «a»). Escribe tú la dirección oficial en vez de pulsar este enlace.');
    }

    // --- imitación de marcas ---
    if (!bracketed && !isIPv4(host)) {
      const tokens = deLeet(host).split(/[.-]/).filter(Boolean);
      const flat = deLeet(host);
      const firstLabel = domain.split('.')[0];
      let flagged = false;
      for (const [brand, official] of Object.entries(BRANDS)) {
        if (official.includes(domain)) continue;
        const inTokens = tokens.includes(brand);
        const inside = brand.length >= 6 && flat.includes(brand);
        const similar = firstLabel !== brand && levenshtein(deLeet(firstLabel), brand) <= (brand.length >= 7 ? 2 : 1) && firstLabel.length >= 4;
        if (inTokens || inside || similar) {
          add(inTokens || inside ? 'bad' : 'warn', 'brand', `Parece imitar a «${brand}»`,
            `La dirección menciona o se parece a «${brand}», pero su dominio real es «${domain}», que no es uno de los oficiales (${official.slice(0, 2).join(', ')}…).`);
          flagged = true;
          break;
        }
      }
      if (!flagged) {
        const known = Object.values(BRANDS).some((list) => list.includes(domain));
        if (known) add('ok', 'brand', 'Dominio oficial conocido', `«${domain}» coincide con un dominio oficial de una marca conocida.`);
      }
    }

    // --- subdominios y palabras señuelo ---
    if (!bracketed && !isIPv4(host)) {
      const subdomainCount = labels.length - domain.split('.').length;
      if (subdomainCount >= 3) {
        add('warn', 'subdomains', 'Demasiados subdominios',
          `Hay ${subdomainCount} niveles antes del dominio real. Es un truco para esconder el dominio verdadero («${domain}») al final.`);
      }
      const registrableLabel = domain.split('.')[0];
      const lure = LURE_WORDS.filter((w) => registrableLabel.includes(w));
      if (lure.length || (registrableLabel.match(/-/g) || []).length >= 3) {
        add('warn', 'lure', 'Palabras de «acción urgente» en el dominio',
          `El nombre del dominio incluye ${lure.length ? '«' + lure.join('», «') + '»' : 'muchos guiones'}. Las estafas imitan avisos de seguridad con ese estilo.`);
      }
      const tld = labels[labels.length - 1];
      if (RISKY_TLDS.has(tld)) {
        add('warn', 'tld', `Extensión «.${tld}» muy usada en estafas`, 'No significa que sea falsa, pero es una extensión barata y frecuente en campañas de phishing.');
      }
      if (SHORTENERS.has(domain)) {
        add('warn', 'shortener', 'Enlace acortado', 'No puedes ver el destino real antes de entrar. Pide el enlace completo o usa un expansor de URL.');
      }
    }

    // --- puerto, datos sensibles en la URL, longitud ---
    if (url.port) {
      add('warn', 'port', `Puerto no estándar (${url.port})`, 'Los sitios normales usan los puertos 80/443 sin mostrarlos. Un puerto raro es poco habitual en un inicio de sesión.');
    }
    const leaked = [...url.searchParams.keys()].filter((k) => SENSITIVE_PARAMS.includes(k.toLowerCase()));
    if (leaked.length) {
      add('bad', 'params', 'Datos sensibles dentro de la dirección',
        `Los parámetros «${leaked.join(', ')}» quedan guardados en el historial, en los registros del servidor y en proxies. Un sitio serio nunca pide contraseñas por la URL.`);
    }
    if (input.length > 200) {
      add('warn', 'long', 'Dirección muy larga', 'Las direcciones larguísimas suelen esconder redirecciones o el dominio real.');
    }

    return finish(url, checks, domain);
  }

  function finish(url, checks, domain) {
    const bad = checks.filter((c) => c.level === 'bad').length;
    const warn = checks.filter((c) => c.level === 'warn').length;
    const risk = bad ? 'alto' : warn ? 'medio' : 'bajo';
    const summary = bad
      ? 'Señales graves: no escribas tu contraseña aquí.'
      : warn
        ? 'Hay señales sospechosas: verifica por otro medio antes de continuar.'
        : 'No vemos señales de alerta evidentes. Eso no garantiza que sea legítima: sigue los demás pasos.';
    return {
      ok: true,
      host: url.hostname,
      domain,
      protocol: url.protocol,
      risk,
      summary,
      checks,
    };
  }

  return { analyze, registrableDomain, levenshtein, BRANDS, MAX_LENGTH };
});
