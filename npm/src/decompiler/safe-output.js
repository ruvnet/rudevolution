'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Use a caller-owned output directory. Reject symlinks and never overwrite files.
function ensureDirectory(directory) {
  const resolved = path.resolve(directory);
  const parent = path.dirname(resolved);
  if (parent !== resolved) ensureDirectory(parent);
  try { fs.mkdirSync(resolved, { mode: 0o700 }); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Unsafe output directory');
}
function writeNewFile(filename, content) {
  ensureDirectory(path.dirname(filename));
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT |
    fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
  try { fs.writeFileSync(fd, content); } finally { fs.closeSync(fd); }
}
function moduleFilename(root, name, index) {
  if (typeof name !== 'string' || !name || /[\\\x00-\x1f\x7f:]/.test(name) ||
      name.split('/').some(p => !p || p === '.' || p === '..')) {
    throw new Error('Invalid module path');
  }
  const relative = name.includes('/') ? `${name}.js` :
    `module-${String(index + 1).padStart(3, '0')}-${name}.js`;
  return path.join(root, relative);
}
module.exports = { ensureDirectory, writeNewFile, moduleFilename };
