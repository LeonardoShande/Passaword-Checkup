/*!
 * attacks.js — convierte el análisis de la contraseña en una lista de "cómo podrían vulnerarla".
 *
 * Compartido entre Node (tests) y el navegador (window.PasswordAttacks).
 * Entrada: el objeto que devuelve PasswordScoring.analyze() + { breachCount }.
 * Salida:  { headline, items[] }  — cada item enlaza a su tarjeta "Más info" (card).
 *
 * risk: 'alto' | 'medio' | 'bajo'  -> depende de la contraseña
 *       'indep'                    -> no depende de su fortaleza (phishing, malware, cookies…)
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PasswordAttacks = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const RANK = { alto: 3, medio: 2, bajo: 1, indep: 0 };

  function assess(analysis, options) {
    const a = analysis;
    if (!a || a.empty) return { headline: '', items: [] };
    const breachCount = (options && options.breachCount) || 0;
    const breached = breachCount > 0;
    const time = (id) => a.crackTimes.find((t) => t.id === id);
    const online = time('online_unthrottled');
    const throttled = time('online_throttled');
    const slow = time('offline_slow');
    const fast = time('offline_fast');

    const items = [
      {
        id: 'online',
        card: 'brute-force',
        title: 'Fuerza bruta contra el formulario',
        risk: breached ? 'alto' : online.risk,
        text: breached
          ? 'Al estar en listas públicas, la probarían entre los primeros intentos.'
          : `Sin límite de intentos: ${online.human}. Con el límite de un sitio serio (100 por hora): ${throttled.human}.`,
      },
      {
        id: 'dictionary',
        card: 'dictionary',
        title: 'Diccionarios y reglas de mutación',
        risk: breached ? 'alto' : a.predictability,
        text: a.patterns.length
          ? `La encontrarían en su primera fase: ${a.patterns.slice(0, 2).map((p) => p.note).join('; ')}.`
          : 'No contiene palabras ni patrones comunes: un diccionario no la encontraría.',
      },
      {
        id: 'leak',
        card: 'leaks',
        title: 'Base de datos del sitio robada',
        risk: breached ? 'alto' : fast.risk,
        text: `Si el sitio la guardó con un hash rápido (MD5/SHA-1): ${fast.human}. Con bcrypt o Argon2: ${slow.human}.`,
      },
      {
        id: 'stuffing',
        card: 'reuse',
        title: 'Relleno de credenciales (si la reutilizas)',
        risk: breached ? 'alto' : 'indep',
        text: breached
          ? `Ya apareció ${breachCount.toLocaleString('es')} veces en filtraciones: los bots la prueban en cientos de sitios.`
          : 'Si usas esta misma clave en otro sitio y se filtra, los bots la prueban en todos los demás. La fortaleza no te protege aquí.',
      },
      {
        id: 'phishing',
        card: 'phishing',
        title: 'Phishing: tú se la entregas',
        risk: 'indep',
        text: 'Una página falsa idéntica a la real te la pide. Ninguna longitud protege; ayudan las passkeys y revisar el dominio.',
      },
      {
        id: 'malware',
        card: 'malware',
        title: 'Keylogger o malware en tu equipo',
        risk: 'indep',
        text: 'Si tu dispositivo está infectado, se captura al escribirla, por muy buena que sea. Ayuda mantener todo actualizado y activar 2FA.',
      },
      {
        id: 'cookies',
        card: 'cookies',
        title: 'Robo de cookie de sesión',
        risk: 'indep',
        text: 'Con tu cookie de sesión entran a tu cuenta sin conocer la contraseña. Ayuda cerrar sesión, HTTPS y revisar sesiones activas.',
      },
    ];

    let headline;
    if (breached) headline = 'Ya apareció en filtraciones: es de las primeras que probaría cualquier atacante.';
    else if (a.isCommon) headline = 'Está en todas las listas de ataque: caería en segundos.';
    else if (a.isPredictable) headline = 'Sigue patrones predecibles: un diccionario con reglas la encontraría rápido.';
    else {
      const worst = items.filter((i) => i.risk !== 'indep').sort((x, y) => RANK[y.risk] - RANK[x.risk])[0];
      headline = worst.risk === 'bajo'
        ? 'Resiste los ataques de adivinación. Tu punto débil ya no es la contraseña, sino cómo la usas (reutilización, phishing, malware).'
        : `Su punto más débil: ${worst.title.toLowerCase()}.`;
    }

    return { headline, items };
  }

  return { assess, RANK };
});
