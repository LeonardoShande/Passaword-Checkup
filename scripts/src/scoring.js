/*!
 * scoring.js — motor de puntaje de contraseñas (sin dependencias).
 *
 * Se usa en dos sitios con el MISMO código:
 *   - Navegador: el servidor lo expone en /shared/scoring.js  -> window.PasswordScoring
 *   - Node:      require('./src/scoring')                      -> tests
 *
 * Idea: estimar la ENTROPÍA EFECTIVA (en bits) y convertirla a un puntaje 0-100.
 *   1. Entropía "ingenua"  = longitud × log2(tamaño del alfabeto usado).
 *   2. Se detectan patrones predecibles (palabras comunes, secuencias, teclado,
 *      repeticiones, años) y cada uno "cuesta" muchos menos bits que escribirlo al azar.
 *   3. Bits -> puntaje con una curva por tramos basada en la tabla clásica de entropía.
 *   4. Topes (caps): contraseñas comunes, cortas o muy predecibles no pueden pasar de cierto puntaje.
 *   5. Tiempo estimado de adivinación con las 4 velocidades "clásicas" de ataque (como zxcvbn).
 *
 * Es una heurística DIDÁCTICA: su diccionario es pequeño a propósito.
 * Para producción combina esto con una lista de filtraciones (HIBP) o con zxcvbn.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PasswordScoring = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const MAX_ANALYZED_LENGTH = 256; // evita trabajo inútil con entradas gigantes

  // ---------------------------------------------------------------------------
  // 1. Diccionario de contraseñas / palabras muy comunes (inglés + español)
  // ---------------------------------------------------------------------------
  const COMMON_ENTRIES = `
    password pass passcode passw0rd welcome login admin administrator root user guest test testing
    letmein master monkey dragon shadow sunshine princess football baseball soccer hockey basketball
    superman batman spiderman starwars pokemon naruto ninja hunter hello freedom whatever trustno1
    iloveyou loveyou lovely secret killer jordan michael jennifer jessica ashley daniel andrew thomas
    robert charlie summer winter spring autumn flower cookie cheese banana orange purple silver golden
    internet computer google facebook youtube amazon apple samsung windows linux matrix changeme
    troubador troubadour
    default system server mypass mypassword access biteme liverpool chelsea arsenal barcelona madrid
    realmadrid qwerty qwertyuiop asdfghjkl zxcvbnm azerty abc123 abcdef abcd abcdefg 1q2w3e 1q2w3e4r
    123qwe qwe123
    contrasena contrasenia clave claves usuario hola holamundo bienvenido amor teamo tequiero miamor
    mivida corazon princesa angel angelito dios jesus familia mama papa carlos maria jose juan luis
    pedro miguel sofia valentina alejandro gabriel fernando rodrigo andrea carolina diego javier
    ricardo peru lima cusco arequipa trujillo alianza universitario cristal melgar futbol messi
    ronaldo cristiano neymar boca river america mexico colombia chile argentina venezuela ecuador
    espana amigos secreto dinero futuro verano invierno estrella mariposa chocolate canela bonita
    hermosa guapo guapa micontrasena
    123456 1234567 12345678 123456789 1234567890 12345 1234 111111 000000 123123 654321 666666
    121212 112233 987654321 7777777 123321 696969 159753 147258369
  `.split(/\s+/).filter(Boolean);

  const ACCENTS = {
    'á': 'a', 'à': 'a', 'ä': 'a', 'â': 'a', 'é': 'e', 'è': 'e', 'ë': 'e', 'ê': 'e',
    'í': 'i', 'ì': 'i', 'ï': 'i', 'î': 'i', 'ó': 'o', 'ò': 'o', 'ö': 'o', 'ô': 'o',
    'ú': 'u', 'ù': 'u', 'ü': 'u', 'û': 'u', 'ñ': 'n',
  };

  // Sustituciones típicas "leet": @ -> a, 0 -> o, $ -> s ...
  const LEET = {
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o',
    '$': 's', '5': 's', '7': 't', '+': 't', '8': 'b', '9': 'g', '6': 'g',
  };

  // Ambas transformaciones conservan la longitud (1 carácter -> 1 carácter),
  // así los índices del texto original sirven para el texto normalizado.
  function toPlain(str) {
    let out = '';
    for (let i = 0; i < str.length; i++) {
      const lower = str[i].toLowerCase();
      out += ACCENTS[lower] || (lower.length === 1 ? lower : str[i]);
    }
    return out;
  }

  function toLeet(plain) {
    let out = '';
    for (let i = 0; i < plain.length; i++) out += LEET[plain[i]] || plain[i];
    return out;
  }

  // Entradas solo numéricas se buscan en el texto tal cual; el resto, con leet aplicado.
  const NUMERIC_WORDS = [];
  const LEET_WORDS = [];
  for (const entry of new Set(COMMON_ENTRIES)) {
    if (/^\d+$/.test(entry)) {
      if (entry.length >= 4) NUMERIC_WORDS.push(entry);
    } else {
      const normalized = toLeet(toPlain(entry));
      if (normalized.length >= 4) LEET_WORDS.push(normalized);
    }
  }
  const DICTIONARY_BITS = 11; // ~2 000 candidatos: lo que "cuesta" adivinar una palabra común

  // ---------------------------------------------------------------------------
  // 2. Alfabeto usado (tamaño del "pool")
  // ---------------------------------------------------------------------------
  function classify(pw) {
    const c = { lower: false, upper: false, digit: false, symbol: false, other: false };
    for (let i = 0; i < pw.length; i++) {
      const code = pw.charCodeAt(i);
      if (code >= 97 && code <= 122) c.lower = true;
      else if (code >= 65 && code <= 90) c.upper = true;
      else if (code >= 48 && code <= 57) c.digit = true;
      else if (code < 128) c.symbol = true; // espacio y puntuación ASCII
      else c.other = true; // acentos, ñ, emojis, otros alfabetos
    }
    return c;
  }

  function poolSize(c) {
    // 20 para "otros" es una estimación conservadora (no 100+ de Unicode completo)
    return (c.lower ? 26 : 0) + (c.upper ? 26 : 0) + (c.digit ? 10 : 0) +
      (c.symbol ? 33 : 0) + (c.other ? 20 : 0);
  }

  // ---------------------------------------------------------------------------
  // 3. Detectores de patrones
  // ---------------------------------------------------------------------------
  const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkln', 'zxcvbnm', 'qazwsxedcrfv'];
  const KEYBOARD_PATTERNS = KEYBOARD_ROWS.concat(KEYBOARD_ROWS.map((r) => r.split('').reverse().join('')));

  function findCommonWords(plain, leet) {
    const found = [];
    for (const w of LEET_WORDS) {
      for (let from = 0, i; (i = leet.indexOf(w, from)) !== -1; from = i + 1) {
        found.push({ start: i, end: i + w.length, numeric: false });
      }
    }
    for (const w of NUMERIC_WORDS) {
      for (let from = 0, i; (i = plain.indexOf(w, from)) !== -1; from = i + 1) {
        found.push({ start: i, end: i + w.length, numeric: true });
      }
    }
    // Primero las coincidencias más largas
    return found.sort((a, b) => (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  }

  function findKeyboardRuns(plain) {
    const out = [];
    for (let i = 0; i < plain.length;) {
      let best = 0;
      for (const row of KEYBOARD_PATTERNS) {
        for (let j = row.indexOf(plain[i]); j !== -1; j = row.indexOf(plain[i], j + 1)) {
          let k = 0;
          while (i + k < plain.length && j + k < row.length && plain[i + k] === row[j + k]) k++;
          if (k > best) best = k;
        }
      }
      if (best >= 4) { out.push({ start: i, end: i + best }); i += best; } else i++;
    }
    return out;
  }

  const isAlnum = (c) => (c >= 48 && c <= 57) || (c >= 97 && c <= 122);

  function findSequences(plain) {
    const out = [];
    const n = plain.length;
    let i = 0;
    while (i < n - 2) {
      const a = plain.charCodeAt(i);
      const b = plain.charCodeAt(i + 1);
      const c = plain.charCodeAt(i + 2);
      const d = b - a;
      const ok = (x, y) => isAlnum(x) && isAlnum(y) && (x <= 57) === (y <= 57);
      if ((d === 1 || d === -1) && c - b === d && ok(a, b) && ok(b, c)) {
        let j = i + 2;
        while (j + 1 < n && plain.charCodeAt(j + 1) - plain.charCodeAt(j) === d &&
          ok(plain.charCodeAt(j), plain.charCodeAt(j + 1))) j++;
        out.push({ start: i, end: j + 1 });
        i = j + 1;
      } else i++;
    }
    return out;
  }

  function findRepeats(plain) {
    const out = [];
    for (let i = 0; i < plain.length;) {
      let j = i + 1;
      while (j < plain.length && plain[j] === plain[i]) j++;
      if (j - i >= 3) out.push({ start: i, end: j });
      i = j;
    }
    return out;
  }

  function findYears(plain) {
    const out = [];
    const re = /(?:19|20)\d{2}/g;
    let m;
    while ((m = re.exec(plain))) out.push({ start: m.index, end: m.index + 4 });
    return out;
  }

  function findRepeatedBlock(plain) {
    const n = plain.length;
    if (n < 4) return null;
    for (let len = 2; len <= n / 2; len++) {
      if (n % len === 0 && plain.slice(0, len).repeat(n / len) === plain) return { len, times: n / len };
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // 4. Bits -> puntaje -> nivel
  // ---------------------------------------------------------------------------
  // Curva por tramos (bits, puntaje). Basada en la tabla clásica de entropía:
  // <28 muy débil · 28-35 débil · 36-59 razonable · 60+ fuerte · 80+ muy fuerte.
  const CURVE = [[0, 0], [28, 20], [36, 40], [60, 60], [80, 80], [100, 100]];

  function scoreFromBits(bits) {
    if (bits <= 0) return 0;
    for (let i = 1; i < CURVE.length; i++) {
      const [b1, s1] = CURVE[i];
      if (bits <= b1) {
        const [b0, s0] = CURVE[i - 1];
        return s0 + ((bits - b0) / (b1 - b0)) * (s1 - s0);
      }
    }
    return 100;
  }

  const LEVELS = [
    { id: 'very-weak', label: 'Muy débil' },
    { id: 'weak', label: 'Débil' },
    { id: 'fair', label: 'Aceptable' },
    { id: 'strong', label: 'Fuerte' },
    { id: 'very-strong', label: 'Muy fuerte' },
  ];

  function levelFor(score) {
    const index = score < 20 ? 0 : score < 40 ? 1 : score < 60 ? 2 : score < 80 ? 3 : 4;
    return { index, ...LEVELS[index] };
  }

  // ---------------------------------------------------------------------------
  // 5. Tiempo estimado de adivinación (4 escenarios clásicos)
  // ---------------------------------------------------------------------------
  const SCENARIOS = [
    { id: 'online_throttled', label: 'Ataque web con límite de intentos',
      detail: '100 intentos por hora (el sitio frena o bloquea)', rate: 100 / 3600 },
    { id: 'online_unthrottled', label: 'Ataque web sin límite',
      detail: '10 intentos por segundo', rate: 10 },
    { id: 'offline_slow', label: 'Base de datos robada · hash lento (bcrypt, Argon2)',
      detail: '10 000 intentos por segundo', rate: 1e4 },
    { id: 'offline_fast', label: 'Base de datos robada · hash rápido (MD5, SHA-1)',
      detail: '10 000 millones de intentos por segundo', rate: 1e10 },
  ];

  const MINUTE = 60, HOUR = 3600, DAY = 86400, MONTH = 2629800, YEAR = 31557600;
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  function humanTime(seconds) {
    if (!Number.isFinite(seconds)) return 'más de mil millones de años';
    if (seconds < 1) return 'al instante';
    if (seconds < MINUTE) return plural(Math.round(seconds), 'segundo', 'segundos');
    if (seconds < HOUR) return plural(Math.round(seconds / MINUTE), 'minuto', 'minutos');
    if (seconds < DAY) return plural(Math.round(seconds / HOUR), 'hora', 'horas');
    if (seconds < MONTH) return plural(Math.round(seconds / DAY), 'día', 'días');
    if (seconds < YEAR) return plural(Math.round(seconds / MONTH), 'mes', 'meses');
    const years = seconds / YEAR;
    if (years < 100) return plural(Math.max(1, Math.round(years)), 'año', 'años');
    if (years < 1000) return plural(Math.round(years / 100), 'siglo', 'siglos');
    if (years < 1e6) {
      const n = Math.round(years / 1000);
      return n === 1 ? 'mil años' : `${n} mil años`;
    }
    if (years < 1e9) {
      const n = Math.round(years / 1e6);
      return n === 1 ? 'un millón de años' : `${n} millones de años`;
    }
    return 'más de mil millones de años';
  }

  function riskFromSeconds(seconds) {
    if (seconds < MONTH) return 'alto';
    if (seconds < YEAR * 100) return 'medio';
    return 'bajo';
  }

  // ---------------------------------------------------------------------------
  // 6. Análisis principal
  // ---------------------------------------------------------------------------
  function analyze(input) {
    let pw = typeof input === 'string' ? input : '';
    const truncated = pw.length > MAX_ANALYZED_LENGTH;
    if (truncated) pw = pw.slice(0, MAX_ANALYZED_LENGTH);
    const n = pw.length;

    if (n === 0) {
      return { empty: true, length: 0, score: 0, level: levelFor(0), effectiveBits: 0,
        checks: [], suggestions: [], patterns: [], crackTimes: [], capReasons: [] };
    }

    const classes = classify(pw);
    const pool = poolSize(classes);
    const bitsPerChar = Math.log2(pool);
    const rawBits = n * bitsPerChar;

    const plain = toPlain(pw);
    const leet = toLeet(plain);

    // --- reclamar tramos de la contraseña que siguen un patrón ---
    const covered = new Array(n).fill(false);
    const spans = [];
    const claim = (type, start, end, bits, note) => {
      for (let i = start; i < end; i++) if (covered[i]) return false;
      for (let i = start; i < end; i++) covered[i] = true;
      spans.push({ type, start, end, bits, note, text: pw.slice(start, end) });
      return true;
    };

    const block = findRepeatedBlock(plain);
    if (block) {
      claim('block', 0, n, block.len * bitsPerChar + Math.log2(block.times),
        `repite «${pw.slice(0, block.len)}» ${block.times} veces`);
    }

    for (const w of findCommonWords(plain, leet)) {
      let leetSubs = 0;
      let hasUpper = false;
      for (let i = w.start; i < w.end; i++) {
        if (!w.numeric && plain[i] !== leet[i]) leetSubs++;
        if (pw[i] !== pw[i].toLowerCase()) hasUpper = true;
      }
      const bits = DICTIONARY_BITS + Math.min(leetSubs, 3) + (hasUpper ? 1 : 0);
      claim('common', w.start, w.end, bits, `palabra o clave muy común «${pw.slice(w.start, w.end)}»`);
    }

    for (const r of findKeyboardRuns(plain)) {
      claim('keyboard', r.start, r.end, bitsPerChar + Math.log2(r.end - r.start) + 2,
        `patrón de teclado «${pw.slice(r.start, r.end)}»`);
    }
    for (const r of findSequences(plain)) {
      claim('sequence', r.start, r.end, bitsPerChar + Math.log2(r.end - r.start) + 1,
        `secuencia «${pw.slice(r.start, r.end)}»`);
    }
    for (const r of findRepeats(plain)) {
      claim('repeat', r.start, r.end, bitsPerChar + Math.log2(r.end - r.start),
        `carácter repetido «${pw.slice(r.start, r.end)}»`);
    }
    for (const r of findYears(plain)) {
      claim('year', r.start, r.end, 7, `año «${pw.slice(r.start, r.end)}»`);
    }

    // --- entropía efectiva: caracteres libres al azar + coste de cada patrón ---
    let freeChars = 0;
    for (let i = 0; i < n; i++) if (!covered[i]) freeChars++;
    const effectiveBits = freeChars * bitsPerChar + spans.reduce((sum, s) => sum + s.bits, 0);

    const hasCommon = spans.some((s) => s.type === 'common');
    const isCommon = spans.length === 1 && spans[0].type === 'common' && spans[0].end - spans[0].start === n;
    const isPredictable = spans.length > 0 && freeChars <= 2 && (hasCommon || spans.length > 1 || n < 12);

    // --- puntaje con topes ---
    const baseScore = scoreFromBits(effectiveBits);
    const caps = [];
    if (isCommon) caps.push({ max: 5, reason: 'Es una contraseña extremadamente común: está en todas las listas de ataque.' });
    else if (isPredictable) caps.push({ max: 25, reason: 'Casi toda la contraseña sigue patrones predecibles.' });
    if (n < 8) caps.push({ max: 39, reason: 'Tiene menos de 8 caracteres (el mínimo aceptable).' });
    else if (n < 12) caps.push({ max: 79, reason: 'Con menos de 12 caracteres no puede considerarse "muy fuerte".' });

    let score = baseScore;
    const capReasons = [];
    for (const cap of caps) {
      if (score > cap.max) { score = cap.max; capReasons.push(cap.reason); }
    }
    score = Math.round(Math.max(0, Math.min(100, score)));
    const level = levelFor(score);

    // --- criterios clásicos (checklist) ---
    const hasKeyboardOrSeq = spans.some((s) => s.type === 'keyboard' || s.type === 'sequence');
    const hasRepeats = spans.some((s) => s.type === 'repeat' || s.type === 'block');
    const checks = [
      { id: 'length', ok: n >= 12, label: 'Al menos 12 caracteres',
        hint: `Tiene ${n}. La longitud es lo que más pesa: apunta a 14 o más.` },
      { id: 'lower', ok: classes.lower, label: 'Letras minúsculas (a-z)', hint: 'Añade letras minúsculas.' },
      { id: 'upper', ok: classes.upper, label: 'Letras mayúsculas (A-Z)', hint: 'Añade letras mayúsculas.' },
      { id: 'digit', ok: classes.digit, label: 'Números (0-9)', hint: 'Añade algún número.' },
      { id: 'symbol', ok: classes.symbol || classes.other, label: 'Símbolos (! ? # $ …)', hint: 'Añade algún símbolo.' },
      { id: 'spaces', ok: !/\s/.test(pw), label: 'Sin espacios',
        hint: 'Muchos sitios recortan o rechazan los espacios. Separa palabras con - o _.' },
      { id: 'common', ok: !isPredictable && !hasCommon, label: 'No usa palabras ni claves comunes',
        hint: 'Evita palabras, nombres y trucos como P@ssw0rd.' },
      { id: 'sequences', ok: !hasKeyboardOrSeq, label: 'Sin secuencias (abc, 123, qwerty)',
        hint: 'Quita secuencias y patrones de teclado.' },
      { id: 'repeats', ok: !hasRepeats, label: 'Sin repeticiones (aaa, abcabc)', hint: 'Evita repetir caracteres o bloques.' },
    ];

    // --- sugerencias (máximo 3, en orden de impacto) ---
    const suggestions = [];
    const failed = (id) => checks.find((c) => c.id === id && !c.ok);
    if (isCommon) suggestions.push('Cámbiala por completo: esta contraseña se prueba en los primeros segundos de cualquier ataque.');
    if (failed('length')) suggestions.push('Alárgala: una frase de 4-5 palabras al azar (con separadores) es fácil de recordar y muy difícil de adivinar.');
    if (failed('common') && !isCommon) suggestions.push('Evita palabras, nombres, fechas y sustituciones típicas (a→@, o→0): los atacantes las prueban primero.');
    if (failed('sequences') || failed('repeats')) suggestions.push('Elimina secuencias (abc, 123, qwerty) y repeticiones (aaa): reducen mucho su fortaleza real.');
    if (!suggestions.length && (failed('upper') || failed('digit') || failed('symbol') || failed('lower'))) {
      suggestions.push('Mezcla tipos de caracteres (mayúsculas, números, símbolos) para ampliar el alfabeto.');
    }
    if (score >= 80) suggestions.push('Muy bien. Guárdala en un gestor de contraseñas, no la repitas en otros sitios y activa la verificación en dos pasos.');

    // --- tiempos de adivinación ---
    const bitsForTime = Math.min(effectiveBits, 1000);
    const crackTimes = SCENARIOS.map((s) => {
      const seconds = Math.pow(2, Math.max(bitsForTime - 1, 0)) / s.rate; // en promedio: la mitad del espacio
      return { id: s.id, label: s.label, detail: s.detail, guessesPerSecond: s.rate,
        seconds, human: humanTime(seconds), risk: riskFromSeconds(seconds) };
    });

    const predictability = isCommon || isPredictable ? 'alto' : spans.length > 0 ? 'medio' : 'bajo';

    return {
      empty: false,
      truncated,
      length: n,
      classes,
      poolSize: pool,
      rawBits: Math.round(rawBits * 10) / 10,
      effectiveBits: Math.round(effectiveBits * 10) / 10,
      score,
      level,
      capReasons,
      isCommon,
      isPredictable,
      predictability,
      patterns: spans.map(({ type, start, end, note }) => ({ type, start, end, note })),
      checks,
      suggestions: suggestions.slice(0, 3),
      crackTimes,
    };
  }

  return { analyze, levelFor, humanTime, scoreFromBits, riskFromSeconds, SCENARIOS, MAX_ANALYZED_LENGTH };
});
