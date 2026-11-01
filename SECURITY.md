# Política de seguridad

## Reportar una vulnerabilidad

Si encuentras un fallo de seguridad **no abras un issue público**. Usa
**Security → Report a vulnerability** en la página del repositorio (avisos privados de GitHub)
o escribe al responsable del repositorio. Incluye pasos para reproducirlo y su impacto.
Se responderá lo antes posible.

## Alcance y garantías del proyecto

- La contraseña se analiza **en el navegador** y nunca se envía al servidor; no existe un endpoint que la reciba.
- Sin dependencias de terceros en ejecución: no hay cadena de suministro de paquetes que vigilar.
- CSP estricta (sin scripts ni estilos inline), cabeceras de seguridad, límite de peticiones y registro mínimo.
- El análisis de URL (`src/urlcheck.js`) es una heurística didáctica: **no sustituye** a un servicio de reputación.

## Verificar un paquete descargado

Cada release incluye el `.zip`, su `.sha256` y una **atestación de procedencia** (GitHub Actions).

```bash
sha256sum -c password-checkup-vX.Y.Z.zip.sha256     # integridad del zip
node scripts/verify.js password-checkup-vX.Y.Z.zip  # rutas seguras, CRC-32 y SHA256SUMS internos
gh attestation verify password-checkup-vX.Y.Z.zip --repo <usuario>/password-checkup   # procedencia
```

El zip es **reproducible**: `npm run package` sobre el mismo código produce el mismo hash.
Ten en cuenta que la integridad no es confidencialidad: el zip no está cifrado.

## Versiones con soporte

Solo la última versión publicada.
