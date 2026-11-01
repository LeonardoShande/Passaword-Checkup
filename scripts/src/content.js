'use strict';

/**
 * Contenido educativo de la página (en español).
 *
 * Cada sección se muestra como una tarjeta con un botón "Más info".
 *  - group: 'threats' | 'advanced' | 'defense'  -> en qué zona de la página aparece
 *  - short: etiqueta corta para los accesos rápidos
 *  - open:  true -> la tarjeta se muestra abierta
 *  - risk.type = 'scenario'       -> el riesgo se toma de un escenario de tiempos de adivinación
 *  - risk.type = 'predictability' -> el riesgo depende de cuán predecible es la contraseña
 *  - risk.type = 'independent'    -> NO depende de la fortaleza (phishing, cookies, logs…)
 *  - risk.type = 'none'           -> tarjeta informativa, sin etiqueta de riesgo
 *  - demo: 'cookies' | 'logs' | 'webcheck' -> mini‑demo interactivo
 *
 * Bloques de `details`: { type: 'p' | 'h' | 'ul' | 'code', text | items }
 *
 * FUENTES: solo organismos y documentación técnica de referencia (CISA, NIST, OWASP, MDN,
 * Google, FIDO…). Los enlaces fueron verificados el 2026-10-25. Un test impide añadir
 * enlaces de dominios que no estén en la lista blanca (p. ej. enciclopedias abiertas).
 */

const p = (text) => ({ type: 'p', text });
const h = (text) => ({ type: 'h', text });
const ul = (...items) => ({ type: 'ul', items });
const code = (text) => ({ type: 'code', text });

const sections = [
  {
    id: 'brute-force',
    group: 'threats',
    short: 'Fuerza bruta',
    icon: '🔨',
    title: 'Fuerza bruta: probar y probar hasta acertar',
    risk: { type: 'scenario', id: 'online_unthrottled' },
    summary:
      'Un programa prueba miles de combinaciones contra el formulario de inicio de sesión. ' +
      'Cuanto más larga e impredecible sea tu contraseña, más tiempo necesita.',
    details: [
      p('En la fuerza bruta pura el atacante prueba todas las combinaciones posibles. Cada carácter extra multiplica el trabajo: ' +
        'pasar de 8 a 12 caracteres significa más de 80 millones de veces más combinaciones (con 95 símbolos posibles).'),
      p('Contra un formulario web el ataque es lento, porque los servidores frenan o bloquean. Por eso los atacantes empiezan ' +
        'por las contraseñas más usadas del mundo antes de probar combinaciones al azar.'),
      p('Lo que hace un sitio bien construido:'),
      ul('Límite de intentos y bloqueos temporales.',
        'Retrasos crecientes o CAPTCHA tras varios fallos.',
        'Verificación en dos pasos (2FA).',
        'Alertas de inicio de sesión sospechoso.'),
    ],
    tips: [
      'Prefiere longitud: 14 o más caracteres, o una frase de 4-5 palabras al azar unidas con guiones.',
      'Evita las contraseñas populares: son las primeras que se prueban.',
    ],
    links: [
      { label: 'OWASP · Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' },
      { label: 'OWASP Top 10 (2025) · A07 Fallos de autenticación', url: 'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/' },
      { label: 'CISA · Usa contraseñas fuertes (EN)', url: 'https://www.cisa.gov/secure-our-world/use-strong-passwords' },
    ],
  },
  {
    id: 'dictionary',
    group: 'threats',
    short: 'Diccionarios',
    icon: '🔎',
    title: 'Diccionarios y patrones predecibles',
    risk: { type: 'predictability' },
    summary:
      'Los atacantes no empiezan por «aaaa»: usan listas de contraseñas reales, nombres, fechas y trucos típicos ' +
      '(P@ssw0rd!, Nombre2024). Si tu clave sigue un patrón, se adivina rápido.',
    details: [
      p('Un ataque de diccionario prueba palabras, nombres propios, equipos de fútbol y fechas, y aplica «reglas de mutación»: ' +
        'mayúscula inicial, cambiar a por @, añadir 123 o el año al final. Por eso «Contraseña2024!» parece compleja pero no lo es.'),
      p('Esta página detecta y penaliza estos patrones:'),
      ul('Palabras comunes y sustituciones tipo leet (a→@, o→0, e→3).',
        'Secuencias: abc, 123, 987.',
        'Patrones de teclado: qwerty, asdf, qazwsx.',
        'Repeticiones: aaaa, abcabc.',
        'Años: 1998, 2024.'),
      p('El diccionario de este proyecto es pequeño a propósito (es didáctico). Un diccionario real tiene millones de entradas: ' +
        'activa la comprobación de filtraciones para acercarte a la realidad.'),
    ],
    tips: [
      'No uses nombres, mascotas, fechas ni equipos.',
      'Una frase larga de palabras sin relación entre sí supera a una «palabra rara con símbolos».',
    ],
    links: [
      { label: 'NIST SP 800-63B-4 · Autenticación y gestión de autenticadores (EN)', url: 'https://www.nist.gov/publications/nist-sp-800-63b-4digital-identity-guidelines-authentication-and-authenticator' },
      { label: 'zxcvbn · Estimador de fortaleza realista', url: 'https://github.com/dropbox/zxcvbn' },
    ],
  },
  {
    id: 'leaks',
    group: 'threats',
    short: 'Filtraciones',
    icon: '🗄️',
    title: 'Filtraciones: cuando roban la base de datos del sitio',
    risk: { type: 'scenario', id: 'offline_fast' },
    summary:
      'Aunque tu clave sea buena, el sitio donde la usas puede ser hackeado. Si la guardó mal, ' +
      'el atacante la descifra en su propio equipo, sin límites ni alarmas.',
    details: [
      p('Los sitios serios no guardan tu contraseña: guardan un «hash», una huella que no se puede revertir. ' +
        'Si roban la base de datos, el atacante prueba millones de candidatas por segundo contra esos hashes, offline, sin que nadie lo note.'),
      p('La velocidad depende de cómo se guardó:'),
      ul('MD5 o SHA-1 sin sal: miles de millones de intentos por segundo con tarjetas gráficas, y tablas «rainbow» ya calculadas.',
        'bcrypt, scrypt o Argon2id con sal única: diseñados para ser lentos y costosos.'),
      p('La «sal» (salt) es un dato aleatorio por usuario. Evita que dos personas con la misma contraseña tengan el mismo hash ' +
        'y deja inútiles las tablas precalculadas.'),
      code('hash_malo  = SHA1("hunter2")                  # rápido y sin sal → fácil de romper\n' +
        'hash_bueno = argon2id("hunter2", sal_unica)    # lento y con sal   → costoso de romper'),
      p('Tú no controlas cómo guarda el sitio tu contraseña. Por eso la tabla de tiempos muestra tanto el caso bueno (hash lento) como el peor (hash rápido).'),
    ],
    tips: [
      'Usa una contraseña distinta en cada sitio.',
      'Comprueba si apareció en filtraciones (casilla opcional bajo el campo).',
      'Si un sitio avisa de una filtración, cambia la clave allí y en cualquier otro sitio donde la repitas.',
    ],
    links: [
      { label: 'OWASP · Password Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html' },
      { label: 'Have I Been Pwned · API de Pwned Passwords (EN)', url: 'https://haveibeenpwned.com/API/v3#PwnedPasswords' },
    ],
  },
  {
    id: 'reuse',
    group: 'threats',
    short: 'Reutilización',
    icon: '🔁',
    title: 'Reutilización: una filtración abre todas tus puertas',
    risk: { type: 'independent' },
    summary:
      'Cuando se filtra un correo con su contraseña, los bots la prueban automáticamente en cientos de sitios. ' +
      'No adivinan nada: usan tu contraseña real.',
    details: [
      p('Se llama relleno de credenciales (credential stuffing). Los atacantes toman pares correo + contraseña filtrados ' +
        'y los prueban en bancos, redes sociales, tiendas y correo. Basta con que repitas la clave en un solo sitio poco seguro.'),
      p('Por eso una contraseña «fuerte» repetida es una contraseña débil: su fortaleza no importa si ya está en una lista.'),
    ],
    tips: [
      'Una contraseña única por cuenta, sobre todo para tu correo (con él se restablecen todas las demás).',
      'Un gestor de contraseñas hace esto sin esfuerzo.',
    ],
    links: [
      { label: 'OWASP · Credential stuffing (EN)', url: 'https://owasp.org/www-community/attacks/Credential_stuffing' },
    ],
  },
  {
    id: 'phishing',
    group: 'threats',
    short: 'Phishing',
    icon: '🎣',
    title: 'Phishing e ingeniería social: te la piden y la entregas',
    risk: { type: 'independent' },
    summary:
      'No hace falta romper nada: una página falsa idéntica a la real te pide iniciar sesión y eres tú quien la entrega. ' +
      'Ninguna contraseña, por larga que sea, protege contra esto.',
    details: [
      p('El phishing llega por correo, SMS, WhatsApp o anuncios, y copia el aspecto de tu banco, tu correo o tu red social.'),
      p('Señales de alerta:'),
      ul('Urgencia o amenaza («tu cuenta será cerrada hoy»).',
        'Dirección parecida pero distinta (paypa1.com, banc0.com).',
        'Te piden la contraseña o un código por chat o teléfono: ningún servicio legítimo lo hace.',
        'Enlaces o adjuntos que no esperabas.'),
      p('Las llaves de acceso (passkeys) y las llaves FIDO2 están atadas al dominio real, así que no funcionan en una página falsa: ' +
        'son la mejor defensa contra el phishing. Más abajo, en la sección avanzada, puedes analizar una dirección sospechosa.'),
    ],
    tips: [
      'Escribe tú mismo la dirección del sitio o usa tus marcadores, en vez de pulsar enlaces de mensajes.',
      'Si tu gestor de contraseñas no autocompleta en un sitio, desconfía: el dominio puede no ser el real.',
      'Activa passkeys o 2FA con llave de seguridad cuando el servicio lo permita.',
    ],
    links: [
      { label: 'CISA · Cómo evitar la ingeniería social y el phishing (EN)', url: 'https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks' },
      { label: 'FIDO Alliance · Passkeys (EN)', url: 'https://fidoalliance.org/passkeys/' },
    ],
  },
  {
    id: 'malware',
    group: 'threats',
    short: 'Malware',
    icon: '👀',
    title: 'Malware, keyloggers y miradas curiosas',
    risk: { type: 'independent' },
    summary:
      'Si tu equipo está infectado, la contraseña más larga del mundo se captura al teclearla. ' +
      'También cuenta quien mira tu pantalla o tu teclado.',
    details: [
      p('Un keylogger registra lo que escribes. Un «infostealer» roba las contraseñas guardadas en el navegador y también tus cookies de sesión. ' +
        'Suelen llegar con programas piratas, «cracks», adjuntos o falsas actualizaciones.'),
      p('El «shoulder surfing» es más simple: alguien mira tu pantalla o tu teclado en un café, el transporte o la oficina.'),
      ul('Mantén sistema, navegador y aplicaciones actualizados.',
        'Instala software solo desde fuentes oficiales.',
        'Usa la protección antimalware de tu sistema.',
        'Activa 2FA: un código de un solo uso no sirve después de usado.'),
    ],
    tips: [
      'Si sospechas de una infección, cambia tus contraseñas desde otro equipo limpio.',
      'Tapa el teclado o usa el autocompletado de un gestor en lugares públicos.',
    ],
    links: [
      { label: 'NIST CSRC · Glosario: key logger (EN)', url: 'https://csrc.nist.gov/glossary/term/key_logger' },
      { label: 'CISA · Cómo evitar la ingeniería social y el phishing (EN)', url: 'https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks' },
    ],
  },
  {
    id: 'network',
    group: 'threats',
    short: 'Red insegura',
    icon: '📶',
    title: 'Red insegura: HTTP, Wi-Fi públicas y «hombre en el medio»',
    risk: { type: 'independent' },
    summary:
      'Si un sitio usa HTTP, lo que envías viaja en texto claro y cualquiera en el camino puede leerlo. ' +
      'HTTPS lo cifra y comprueba que hablas con el servidor correcto.',
    details: [
      p('En una Wi-Fi abierta, un atacante cercano puede observar o modificar el tráfico que no esté cifrado.'),
      ul('Wi-Fi gemela («evil twin»): una red falsa con el nombre de una legítima.',
        'Ataque de hombre en el medio (MITM): alguien intercepta y altera la comunicación.',
        'Degradación a HTTP: se evita con HSTS, que obliga al navegador a usar siempre HTTPS.'),
      p('El candado indica que la conexión está cifrada, no que el sitio sea honesto: una página de phishing también puede tener HTTPS.'),
    ],
    tips: [
      'No inicies sesión en sitios sin HTTPS.',
      'En Wi-Fi públicas, evita operaciones sensibles o usa los datos móviles.',
      'Presta atención a las advertencias de certificado del navegador: no las ignores.',
    ],
    links: [
      { label: 'MDN · Transport Layer Security (EN)', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Transport_Layer_Security' },
      { label: 'MDN · Strict-Transport-Security (HSTS) (EN)', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security' },
    ],
  },
  {
    id: 'cookies',
    group: 'threats',
    short: 'Cookies',
    icon: '🍪',
    title: 'Cookies y sesiones: el atajo que no necesita tu contraseña',
    risk: { type: 'independent' },
    demo: 'cookies',
    summary:
      'Tras iniciar sesión, el sitio te da una cookie de sesión: un «pase» que dice quién eres. ' +
      'Quien lo robe entra a tu cuenta sin conocer tu contraseña.',
    details: [
      p('HTTP no recuerda nada entre peticiones. Para no pedirte la contraseña en cada clic, el servidor te entrega una cookie ' +
        '(un texto corto con un identificador de sesión) y tu navegador la reenvía automáticamente. ' +
        'Mientras sea válida, esa cookie ES tu identidad.'),
      p('Cómo se roban o se abusa de ellas:'),
      ul('XSS: un script inyectado en la página lee document.cookie (se evita con HttpOnly).',
        'Espionaje de red en HTTP (se evita con Secure y HTTPS).',
        'Malware «infostealer» que copia las cookies del navegador.',
        'CSRF: otro sitio aprovecha que tu navegador envía la cookie solo (se mitiga con SameSite).',
        'Fijación de sesión: el atacante te impone un identificador que ya conoce (el servidor debe renovarlo al iniciar sesión).'),
      p('Atributos que protegen una cookie:'),
      ul('HttpOnly: JavaScript no puede leerla.',
        'Secure: solo viaja por HTTPS.',
        'SameSite=Lax o Strict: no se envía en peticiones entre sitios.',
        'Max-Age / Expires: caduca pronto.',
        'Prefijo __Host-: obliga Secure, Path=/ y la ata a un solo dominio.'),
      p('Ojo: el 2FA se pide al iniciar sesión; una cookie ya robada suele saltarse ese paso. ' +
        'Las cookies de publicidad y analítica de terceros no roban sesiones, pero rastrean lo que haces: es un tema de privacidad distinto.'),
      p('Pulsa el botón para ver cómo este servidor envía dos cookies de demostración, una bien protegida y otra descuidada, ' +
        'y qué puede leer un script malicioso.'),
    ],
    tips: [
      'Cierra sesión en equipos compartidos.',
      'Revisa los dispositivos y sesiones activas de tus cuentas y cierra las que no reconozcas.',
      'Ante una sospecha de malware, cambia contraseñas desde un equipo limpio y cierra todas las sesiones.',
    ],
    links: [
      { label: 'MDN · Cabecera Set-Cookie (EN)', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie' },
      { label: 'OWASP · Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
    ],
  },
  {
    id: 'logs',
    group: 'threats',
    short: 'Registros',
    icon: '📜',
    title: 'Registros (logs): lo que queda anotado',
    risk: { type: 'independent' },
    demo: 'logs',
    summary:
      'Casi todo servidor anota lo que ocurre: quién entró, cuándo, desde dónde y si falló. ' +
      'Sirven para detectar ataques, pero mal hechos pueden filtrar tu contraseña.',
    details: [
      p('Un registro típico contiene fecha y hora, dirección IP, método y ruta, código de estado, navegador (user-agent) y, a veces, el usuario:'),
      code('2026-10-25T22:10:05Z  203.0.113.7  POST /login  401  "Mozilla/5.0 …"  user=ana'),
      p('Para qué sirven:'),
      ul('Detectar fuerza bruta (decenas de fallos seguidos desde una IP).',
        'Avisarte de inicios de sesión inusuales.',
        'Investigar incidentes y cumplir auditorías.'),
      p('Cuándo se vuelven un riesgo:'),
      ul('Contraseñas en la URL (/login?user=ana&clave=1234): quedan en los logs del servidor, de proxies, en el historial del navegador y en la cabecera Referer.',
        'Cuerpos de petición registrados por error al depurar.',
        'Logs sin control de acceso o guardados para siempre.',
        'IP y datos personales sin minimizar.'),
      p('Buenas prácticas para quien programa: nunca registrar secretos, enmascarar datos sensibles, guardar solo lo necesario, ' +
        'retención corta, acceso restringido y alertas.'),
      p('En esta página tu contraseña nunca llega al servidor. El registro de demostración guarda solo método, ruta (sin parámetros), ' +
        'estado, duración, IP anonimizada (hash con sal) y navegador. Pulsa el botón para ver tus propias entradas.'),
    ],
    tips: [
      'Nunca envíes contraseñas dentro de una URL.',
      'Activa los avisos de inicio de sesión de tus cuentas importantes.',
      'En redes o equipos ajenos, recuerda que pueden registrar a qué dominios te conectas, aunque no el contenido bajo HTTPS.',
    ],
    links: [
      { label: 'OWASP Top 10 (2025) · A09 Fallos de registro y alertas (EN)', url: 'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/' },
    ],
  },

  // ---------------------------------------------------------------- AVANZADO
  {
    id: 'web-real',
    group: 'advanced',
    short: 'Web real',
    icon: '🛰️',
    open: true,
    title: 'Avanzado: ¿es segura la web donde pondré mi contraseña real?',
    risk: { type: 'none' },
    demo: 'webcheck',
    summary:
      'Antes de escribir tu contraseña real en un sitio, haz esta revisión de 30 segundos. ' +
      'Ninguna señal sola es garantía, pero juntas descartan casi todas las estafas comunes.',
    details: [
      h('1 · Lee bien la dirección'),
      p('El dominio real es lo que está justo antes de la primera barra «/». En «login.banco.com.estafa.xyz» el dominio es estafa.xyz, no banco.com: ' +
        'lo importante está al final, no al principio.'),
      ul('Desconfía de errores sutiles (paypa1.com, rnicrosoft.com), guiones de más (banco-seguro-login.com) y letras de otros alfabetos.',
        'Lo que va antes de una @ es solo un «usuario»: https://banco.com@estafa.xyz te lleva a estafa.xyz.'),
      h('2 · Comprueba la conexión (HTTPS)'),
      p('Pulsa el icono junto a la dirección (candado o controles) y entra a «La conexión es segura» → certificado. Debe estar emitido para ese mismo dominio y vigente. ' +
        'Ojo: el candado solo prueba que la conexión va cifrada; las páginas de phishing también lo tienen.'),
      h('3 · Mira cómo llegaste'),
      ul('Escribe la dirección tú mismo o usa un marcador; no pulses enlaces de correos, SMS o anuncios.',
        'Si tu gestor de contraseñas no autocompleta, el dominio probablemente no es el que guardaste: es una alarma.',
        'Con passkeys, un sitio falso simplemente no puede pedírtelas: otra ventaja.'),
      h('4 · Revisa el formulario (nivel avanzado)'),
      p('Abre las herramientas de desarrollo (F12) → pestaña Red (Network), activa «Conservar registro» e inicia sesión con datos falsos. Comprueba que:'),
      ul('La petición de login es POST, va por https:// y al mismo dominio (o a un proveedor de inicio de sesión que reconozcas).',
        'La contraseña viaja en el cuerpo de la petición, nunca en la dirección (URL).',
        'En las cabeceras de la respuesta aparecen Strict-Transport-Security y Content-Security-Policy: no prueban honestidad, pero indican un sitio cuidado.'),
      h('5 · Comprueba su reputación'),
      ul('Estado del sitio en Google Safe Browsing (enlace abajo).',
        'Calidad de su HTTPS con SSL Labs y de sus cabeceras con Security Headers (enlaces abajo).'),
      h('6 · Señales de alarma'),
      ul('Urgencia («actúa en 24 horas»), premios, amenazas de cierre de cuenta.',
        'Pide contraseña, código de verificación y datos de tarjeta en la misma pantalla.',
        'Ventanas emergentes que imitan un inicio de sesión, o códigos QR de origen desconocido.'),
      p('Abajo tienes dos herramientas: una analiza una dirección sin conectarse a ella (todo ocurre en tu navegador) ' +
        'y la otra revisa las cabeceras de seguridad de esta misma página, para que veas cómo se hace.'),
    ],
    tips: [
      'Si dudas, no escribas nada: cierra la pestaña y entra escribiendo tú la dirección oficial.',
      'Para tu banco o correo, guarda un marcador la primera vez y úsalo siempre.',
      'Una contraseña real solo debe escribirse en el sitio real, nunca «para probar» en un verificador de terceros.',
    ],
    links: [
      { label: 'Chrome · Cómo comprobar si la conexión de un sitio es segura (EN)', url: 'https://support.google.com/chrome/answer/95617' },
      { label: 'Google Safe Browsing · Estado de un sitio (EN)', url: 'https://transparencyreport.google.com/safe-browsing/search' },
      { label: 'Qualys SSL Labs · Prueba de HTTPS (EN)', url: 'https://www.ssllabs.com/ssltest/' },
      { label: 'Security Headers · Analiza las cabeceras de un sitio (EN)', url: 'https://securityheaders.com/' },
      { label: 'CISA · Cómo evitar la ingeniería social y el phishing (EN)', url: 'https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks' },
    ],
  },

  // ---------------------------------------------------------------- DEFENSA
  {
    id: 'defense',
    group: 'defense',
    short: 'Protégete',
    icon: '🛡️',
    title: 'Cómo protegerte de verdad (resumen)',
    risk: { type: 'none' },
    summary: 'Cinco hábitos que cubren casi todos los escenarios anteriores.',
    details: [
      ul('Longitud antes que complejidad: 14 o más caracteres, o una frase de 4-5 palabras al azar unidas con guiones (método diceware).',
        'Una contraseña distinta por cuenta, guardadas en un gestor de contraseñas.',
        'Activa la verificación en dos pasos, mejor con passkeys o llave FIDO2 (resistentes al phishing).',
        'Comprueba filtraciones y cambia la clave si aparece. No hace falta cambiarla cada cierto tiempo sin motivo.',
        'Mantén tus dispositivos actualizados, usa HTTPS y cierra sesión en equipos ajenos.'),
      p('Los criterios clásicos de esta página (mayúsculas, números, símbolos) son una guía didáctica. ' +
        'La guía vigente de NIST (SP 800-63B) prioriza la longitud, bloquear contraseñas comunes o filtradas y no imponer reglas de composición.'),
      p('Una decisión de diseño de este verificador: no admite espacios. NIST recomienda que los sitios los acepten, pero en la práctica muchos los recortan o los rechazan, ' +
        'así que aquí te sugerimos separar palabras con «-» o «_» para que tu frase funcione en cualquier parte.'),
    ],
    tips: [],
    links: [
      { label: 'NIST SP 800-63B-4 (EN)', url: 'https://www.nist.gov/publications/nist-sp-800-63b-4digital-identity-guidelines-authentication-and-authenticator' },
      { label: 'OWASP · Multifactor Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html' },
      { label: 'CISA · Usa contraseñas fuertes (EN)', url: 'https://www.cisa.gov/secure-our-world/use-strong-passwords' },
    ],
  },
];

// Dominios permitidos para enlaces de fuentes (lo comprueba un test).
const ALLOWED_LINK_HOSTS = [
  'cisa.gov', 'nist.gov', 'owasp.org', 'developer.mozilla.org', 'google.com',
  'ssllabs.com', 'securityheaders.com', 'haveibeenpwned.com', 'fidoalliance.org', 'github.com',
];

module.exports = {
  version: 2,
  sections,
  ALLOWED_LINK_HOSTS,
};
