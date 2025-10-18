const path = require('path');
const os = require('os');

// Determine current platform
function getPlatform() {
  const type = os.platform();
  const arch = os.arch();

  if (type === 'darwin') {
    if (arch === 'x64') return 'darwin-x64';
    if (arch === 'arm64') return 'darwin-arm64';
  }
  if (type === 'linux') {
    if (arch === 'x64') return 'linux-x64-gnu';
    if (arch === 'arm64') return 'linux-arm64-gnu';
  }
  if (type === 'win32') {
    if (arch === 'x64') return 'win32-x64-msvc';
  }

  throw new Error(`Unsupported platform: ${type}-${arch}`);
}

const platform = getPlatform();

// Try to load the native module
const attempts = [
  // Platform-specific directory (for universal package)
  path.join(__dirname, platform, `index.${platform}.node`),
  // Fallback to old single-binary location
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
throw new Error(`Failed to load Asherah native addon for ${platform}${detail}`);
