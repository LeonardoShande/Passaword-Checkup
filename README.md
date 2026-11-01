```text
 ____   _____   ____  _   _  ____   ___  _____ __   __
/ ___| | ____| / ___|| | | ||  _ \ |_ _||_   _|\ \ / /
\___ \ |  _|  | |    | | | || |_) | | |   | |   \ V /
 ___) || |___ | |___ | |_| ||  _ <  | |   | |    | |
|____/ |_____| \____| \___/ |_| \_\|___|  |_|    |_|

 _____  _____   ____  _   _
|_   _|| ____| / ___|| | | |
  | |  |  _|  | |    | |_| |
  | |  | |___ | |___ |  _  |
  |_|  |_____| \____||_| |_|
```

<p align="center"><img src="public/baner.js" alt="Logo de Security Tech" width="120"></p>

# Security Tech · Check-up de contraseñas

Página educativa donde escribes una contraseña y, debajo, ves **qué tan segura es** y **de cuántas formas podrían vulnerarla en la web**. Backend Node sin dependencias + frontend HTML/CSS/JS.

```text
 .      *        _.-""""""-._      .             /\        +
     .         .-'  .   .   '-.        *        /  \    .
   ==========.-----------------.==========     | () |
  *          '.   .    .   .  .'       .       |    |  *
        .        '-.......-'        +        /_|____|_\     .
```

## Novedades de la v1.3

- **Diseño renovado**: puntaje con brillo y escala de 5 niveles, lista de ataques con barra de color por riesgo y «Más info →» discreto, amenazas en rejilla de 2 columnas (la tarjeta abierta ocupa todo el ancho), titular con degradado y sellos de privacidad en el hero. El modo ASCII conserva su estilo.

## Novedades de la v1.2

- **Modo ASCII para toda la página**: botón `ASCII ON/OFF` en la cabecera. Convierte tarjetas en marcos `+----+`, botones en `[ así ]`, títulos en `# Markdown`, la barra de puntaje en `[#####.....]` y el menú en `[01]`, con tipografía monoespaciada y rótulo SECURITY TECH en ASCII.
- **Dos versiones**: *oscura* (terminal de fósforo verde con líneas CRT) y *clara* (papel e tinta). Sigue el botón de tema y se recuerda entre visitas (`localStorage`).
- Sin romper la CSP: los marcos y la textura se generan como SVG con caracteres reales (`public/ascii.js`) y se aplican con variables CSS.

## Novedades de la v1.1

- **Intro animada «SECURITY TECH»** con logo y arte ASCII. Se salta con **ESC**, **tocando la pantalla** o el botón *Saltar*; la pista está visible. Se muestra una vez por sesión y se repite desde el menú o el pie. Respeta `prefers-reduced-motion`.
- **Logo** propio (escudo con órbita y cerradura): `public/logo.svg` y favicon.
- **Menú lateral** (01–06) con resaltado según el scroll; en móvil pasa a barra inferior.
- **Tema oscuro y claro** con arte ASCII espacial distinto para cada uno y fondo de estrellas animado. Sigue al sistema y se puede cambiar a mano.
- **«Cómo podrían vulnerarla»**: mientras escribes, un panel lista 7 vías de ataque con su riesgo, el tiempo estimado y un botón *Más info* a su tarjeta.
- **Sin espacios**: no se pueden teclear; si se pegan, se eliminan con aviso.
- **Avanzado · ¿Es segura la web de mi contraseña real?**: guía de 6 pasos, **analizador de URL** (HTTPS, dominio real, imitación de marcas, truco de la @, IP, punycode, acortadores, datos en la URL…) y **revisión de cabeceras de seguridad** de la propia página. Todo local: no abre la dirección.
- **Fuentes más fiables**: se quitó Wikipedia; ahora CISA, NIST, OWASP, MDN, Google, FIDO y HIBP. Un test impide añadir dominios fuera de la lista.
- **Zip seguro y reproducible** (ver más abajo).

## Ejecutar

Requiere **Node.js 20 o superior**.

```bash
npm start            # http://127.0.0.1:3000
npm run dev          # con recarga automática
npm test             # tests (node:test, sin instalar nada)
npm run package      # genera dist/password-checkup-vX.Y.Z.zip seguro
```

| Variable      | Por defecto | Para qué                                                                  |
|---------------|-------------|---------------------------------------------------------------------------|
| `PORT`        | `3000`      | Puerto                                                                    |
| `HOST`        | `127.0.0.1` | Usa `0.0.0.0` en contenedores o hosting                                   |
| `TRUST_PROXY` | _(vacío)_   | `1` si hay un proxy de confianza (IP real, `https` real y cabecera HSTS) |

## Estructura

```text
password-checkup/
├── server.js              Backend (Node http, sin dependencias)
├── src/
│   ├── scoring.js         Puntaje de contraseñas (compartido Node/navegador)
│   ├── attacks.js         «Cómo podrían vulnerarla» a partir del análisis
│   ├── urlcheck.js        Analizador de URL (sin red)
│   └── content.js         Contenido educativo y fuentes
├── public/
│   ├── index.html · styles.css · app.js
│   ├── theme.js           Tema sin parpadeo + decide si hay intro
│   ├── intro.js           Intro animada (ESC / tap / botón)
│   ├── art.js             Arte ASCII espacial y rótulo (oscuro y claro)
│   ├── ascii.js           Motor del modo ASCII (marcos, barra, textura)
│   └── logo.svg · favicon.svg
├── scripts/               package.js · verify.js · banner.js
├── test/                  tests (puntaje, URL, servidor, paquete)
└── .github/               CI, CodeQL, Release con atestación, Dependabot
```

## Cómo se calcula el puntaje

1. **Entropía ingenua** = `longitud × log2(tamaño del alfabeto)` (26 minúsculas, 26 mayúsculas, 10 dígitos, 33 símbolos, 20 otros).
2. **Entropía efectiva**: cada patrón detectado «cuesta» menos bits que escribirlo al azar.

   | Patrón                                  | Coste en bits                             |
   |-----------------------------------------|-------------------------------------------|
   | Palabra o clave común (con leet)        | 11 (+1 mayúscula, +1 por sustitución)     |
   | Patrón de teclado (`asdf`)              | bits/carácter + log2(largo) + 2           |
   | Secuencia (`abc`, `4567`)               | bits/carácter + log2(largo) + 1           |
   | Repetición (`aaaa`) / bloque (`abcabc`) | bits/carácter + log2(repeticiones)        |
   | Año (`1998`)                            | 7                                         |

3. **Bits → puntaje** por tramos: <28 → 0–19 · 28–35 → 20–39 · 36–59 → 40–59 · 60–79 → 60–79 · ≥80 → 80–100.
4. **Topes**: común → máx. 5 · casi todo patrones → máx. 25 · <8 caracteres → máx. 39 · <12 → máx. 79.
5. **Tiempos** (promedio = mitad del espacio): web con límite (100/h), web sin límite (10/s), base robada con hash lento (10 mil/s) y con hash rápido (10 mil millones/s).

### Limitaciones

- El diccionario es **pequeño a propósito**; un atacante real usa millones de entradas. En producción combina esto con [zxcvbn](https://github.com/dropbox/zxcvbn) o una lista de filtraciones.
- El analizador de URL es una **heurística**: sin alertas no significa que el sitio sea legítimo.
- Rechazar espacios es una decisión de diseño del verificador. NIST SP 800-63B recomienda que *los sitios* los acepten, pero muchos los recortan, así que aquí se sugiere separar con `-` o `_`.

## Seguridad y privacidad de la app

- **La contraseña nunca llega al servidor** (no existe `/api/analyze`).
- **CSP estricta** sin inline, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP y **HSTS** cuando la conexión es HTTPS.
- **Registro mínimo**: método, ruta *sin query string*, estado, duración, IP anonimizada (SHA-256 con sal por arranque) y navegador.
- **Límite de peticiones** en `/api/*`, bloqueo de path traversal y lista blanca de los únicos módulos que se exponen en `/shared/`.
- DOM construido con `createElement`/`textContent`; sin `innerHTML` con datos.

## 🔐 Seguridad del zip

`npm run package` genera `dist/password-checkup-vX.Y.Z.zip` y su `.sha256`:

```text
+-----------------------------+----------------------------------------------+
| Lista blanca                | solo archivos regulares; sin node_modules,   |
|                             | .git, dist, .env, ocultos ni symlinks        |
| Escáner de secretos         | claves privadas, tokens, rutas locales: si   |
|                             | aparece algo, NO genera el paquete           |
| Reproducible                | orden fijo, fecha fija, permisos 0644, sin   |
|                             | compresión: mismo código = mismo hash        |
| SHA256SUMS + MANIFEST.txt   | hash de cada archivo dentro del zip          |
| <zip>.sha256                | hash del zip, aparte                         |
| Verificador                 | rutas seguras (anti zip-slip), límites (anti |
|                             | zip-bomb), CRC-32, hashes y carpeta raíz     |
| Release con atestación      | procedencia firmada con Sigstore (Actions)   |
+-----------------------------+----------------------------------------------+
```

```bash
sha256sum -c password-checkup-v1.3.0.zip.sha256      # integridad del zip
node scripts/verify.js password-checkup-v1.3.0.zip   # revisión interna completa
unzip -z password-checkup-v1.3.0.zip                 # banner y comandos de verificación
```

> La integridad **no es confidencialidad**: el zip no va cifrado. Si necesitas cifrarlo, hazlo aparte (por ejemplo con `age` o 7-Zip AES-256) y comparte la clave por otro canal.

Más detalles y cómo reportar vulnerabilidades: [SECURITY.md](SECURITY.md).

## API

| Método | Ruta                                          | Descripción                                    |
|--------|-----------------------------------------------|------------------------------------------------|
| GET    | `/api/health`                                 | Estado                                         |
| GET    | `/api/content`                                | Secciones por grupo (amenazas, avanzado, defensa) |
| GET    | `/api/demo/session`                           | 2 cookies de demostración y sus atributos      |
| GET    | `/api/demo/logs`                              | Tus últimas entradas del registro (IP anónima) |
| GET    | `/shared/scoring.js · attacks.js · urlcheck.js` | Módulos compartidos con el navegador           |

## Publicar en GitHub

```bash
cd password-checkup
git init -b main
git add .
git commit -m "Security Tech v1.3"
gh repo create password-checkup --public --source=. --push

# Release firmada con atestación:
git tag v1.3.0 && git push --tags
```

Antes de publicar, reemplaza `<TU NOMBRE>` en `LICENSE`. En *Settings → Code security* activa Dependabot y los avisos privados de seguridad.

## Licencia

MIT. Ver `LICENSE`.
