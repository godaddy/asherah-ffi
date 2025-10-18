const path = require('path');

const attempts = [
  path.join(__dirname, 'asherah.node'),
  path.join(__dirname, '..', 'index.node'),
];

let lastErr = null;
for (const candidate of attempts) {
  try {
    module.exports = require(candidate);
    module.exports.__binary = candidate;
    return;
  } catch (err) {
    lastErr = err;
    if (
      err.code !== 'MODULE_NOT_FOUND' &&
      err.code !== 'ERR_MODULE_NOT_FOUND' &&
      err.code !== 'ERR_DLOPEN_FAILED'
    ) {
      throw err;
    }
  }
}

const detail = lastErr ? `: ${lastErr.message || String(lastErr)}` : '';
throw new Error('Failed to load Asherah native addon' + detail);
