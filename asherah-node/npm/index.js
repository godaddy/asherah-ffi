const path = require('path');

const attempts = [
  path.join(__dirname, 'asherah.node'),
  path.join(__dirname, '..', 'index.node'),
];

for (const candidate of attempts) {
  try {
    module.exports = require(candidate);
    module.exports.__binary = candidate;
    return;
  } catch (err) {
    if (
      err.code !== 'MODULE_NOT_FOUND' &&
      err.code !== 'ERR_MODULE_NOT_FOUND' &&
      err.code !== 'ERR_DLOPEN_FAILED'
    ) {
      throw err;
    }
  }
}

throw new Error('Failed to load Asherah native addon.');
