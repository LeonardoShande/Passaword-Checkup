'use strict';

/** Rótulo ASCII «SECURITY TECH» (solo caracteres ASCII: seguro para el comentario del zip). */
const GLYPHS = {
  S: [' ____  ', '/ ___| ', '\\___ \\ ', ' ___) |', '|____/ '],
  E: [' _____ ', '| ____|', '|  _|  ', '| |___ ', '|_____|'],
  C: ['  ____ ', ' / ___|', '| |    ', '| |___ ', ' \\____|'],
  U: [' _   _ ', '| | | |', '| | | |', '| |_| |', ' \\___/ '],
  R: [' ____  ', '|  _ \\ ', '| |_) |', '|  _ < ', '|_| \\_\\'],
  I: [' ___ ', '|_ _|', ' | | ', ' | | ', '|___|'],
  T: [' _____ ', '|_   _|', '  | |  ', '  | |  ', '  |_|  '],
  Y: ['__   __', '\\ \\ / /', ' \\ V / ', '  | |  ', '  |_|  '],
  H: [' _   _ ', '| | | |', '| |_| |', '|  _  |', '|_| |_|'],
};

function word(text) {
  const rows = ['', '', '', '', ''];
  for (const ch of text) for (let r = 0; r < 5; r++) rows[r] += GLYPHS[ch][r];
  return rows.map((l) => l.replace(/\s+$/, ''));
}

const BANNER = [...word('SECURITY'), '', ...word('TECH')].join('\n');

/** Dibuja un recuadro ASCII de ancho fijo con las líneas dadas. */
function box(lines, width = 76, edge = '+', h = '-', v = '|') {
  const inner = width - 2;
  const top = edge + h.repeat(inner) + edge;
  const body = lines.map((l) => v + (' ' + l).padEnd(inner).slice(0, inner) + v);
  return [top, ...body, top].join('\n');
}

module.exports = { BANNER, box, word };
