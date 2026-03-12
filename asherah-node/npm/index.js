const path = require('path');
const os = require('os');

// Detect musl libc (Alpine Linux, etc.)
function isMusl() {
  if (os.platform() !== 'linux') return false;
  try {
    // Node 18+: process.report.getReport() exposes glibc version
    const report = process.report.getReport();
    const header = typeof report === 'string' ? JSON.parse(report).header : report.header;
    return !header.glibcVersionRuntime;
  } catch {
    // Fallback: check for musl dynamic linker
    try {
      return require('fs').readdirSync('/lib').some(f => f.startsWith('ld-musl-'));
    } catch {
      return false;
    }
  }
}

// Determine current platform
function getPlatform() {
  const type = os.platform();
  const arch = os.arch();

  if (type === 'darwin') {
    if (arch === 'x64') return 'darwin-x64';
    if (arch === 'arm64') return 'darwin-arm64';
  }
  if (type === 'linux') {
    const libc = isMusl() ? 'musl' : 'gnu';
    if (arch === 'x64') return `linux-x64-${libc}`;
    if (arch === 'arm64') return `linux-arm64-${libc}`;
  }
  if (type === 'win32') {
    if (arch === 'x64') return 'win32-x64-msvc';
  }

  throw new Error(`Unsupported platform: ${type}-${arch}`);
}

const platform = getPlatform();

// Map platform to npm package name (win32 needed a different name to avoid npm spam filter)
const PLATFORM_PACKAGES = {
  'darwin-arm64': 'asherah-darwin-arm64',
  'darwin-x64': 'asherah-darwin-x64',
  'linux-x64-gnu': 'asherah-linux-x64-gnu',
  'linux-arm64-gnu': 'asherah-linux-arm64-gnu',
  'linux-x64-musl': 'asherah-linux-x64-musl',
  'linux-arm64-musl': 'asherah-linux-arm64-musl',
  'win32-x64-msvc': 'asherah-windows-x64',
};
const packageName = PLATFORM_PACKAGES[platform] || `asherah-${platform}`;

// Try to load the native module:
// 1. Installed platform package (optionalDependency) — normal npm install
// 2. Bundled in platform subdirectory — development / CI builds
// 3. Legacy single-binary fallback
let native = null;
let lastErr = null;

const attempts = [
  // Platform package installed as optionalDependency (e.g., asherah-darwin-arm64)
  packageName,
  // Bundled in platform subdirectory (development builds)
  path.join(__dirname, platform, `index.${platform}.node`),
  // Fallback to old single-binary locations
  path.join(__dirname, 'asherah.node'),
  path.join(__dirname, '..', 'index.node'),
];

for (const candidate of attempts) {
  try {
    native = require(candidate);
    native.__binary = candidate;
    break;
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

if (!native) {
  const detail = lastErr ? `: ${lastErr.message || String(lastErr)}` : '';
  throw new Error(
    `Failed to load Asherah native addon for ${platform}. ` +
    `Ensure the platform package '${packageName}' is installed${detail}`
  );
}

// --- Canonical godaddy/asherah-node compatibility layer ---

// PascalCase → camelCase config field mapping
const CONFIG_MAP = {
  ServiceName: 'serviceName',
  ProductID: 'productId',
  ExpireAfter: 'expireAfter',
  CheckInterval: 'checkInterval',
  Metastore: 'metastore',
  ConnectionString: 'connectionString',
  DynamoDBEndpoint: 'dynamoDBEndpoint',
  DynamoDBRegion: 'dynamoDBRegion',
  DynamoDBTableName: 'dynamoDBTableName',
  SessionCacheMaxSize: 'sessionCacheMaxSize',
  SessionCacheDuration: 'sessionCacheDuration',
  KMS: 'kms',
  RegionMap: 'regionMap',
  PreferredRegion: 'preferredRegion',
  EnableRegionSuffix: 'enableRegionSuffix',
  EnableSessionCaching: 'enableSessionCaching',
  Verbose: 'verbose',
  SQLMetastoreDBType: 'sqlMetastoreDBType',
  ReplicaReadConsistency: 'replicaReadConsistency',
  DisableZeroCopy: 'disableZeroCopy',
  NullDataCheck: 'nullDataCheck',
  EnableCanaries: 'enableCanaries',
};

// Legacy/debug metastore aliases (match Go behavior)
const METASTORE_ALIASES = {
  'test-debug-memory': 'memory',
  'test-debug-sqlite': 'sqlite',
  'test-debug-static': 'static',
};

// Legacy/debug KMS aliases
const KMS_ALIASES = {
  'test-debug-static': 'static',
};

function normalizeConfig(config) {
  // Detect PascalCase format by checking for ServiceName (capital S)
  if (!config || typeof config !== 'object' || !('ServiceName' in config)) {
    return config;
  }

  const out = {};
  for (const [key, value] of Object.entries(config)) {
    const mapped = CONFIG_MAP[key];
    if (mapped === undefined) {
      // Unknown field — pass through as-is (may be a camelCase field mixed in)
      out[key] = value;
    } else if (mapped !== null) {
      out[mapped] = value;
    }
    // mapped === null means ignored (Go-specific)
  }

  // Normalize metastore aliases
  if (typeof out.metastore === 'string') {
    const lower = out.metastore.toLowerCase();
    out.metastore = METASTORE_ALIASES[lower] || lower;
  }

  // Normalize KMS aliases
  if (typeof out.kms === 'string') {
    const lower = out.kms.toLowerCase();
    out.kms = KMS_ALIASES[lower] || lower;
  }

  return out;
}

// Log level mapping: Rust level string → zerolog numeric (used by Go asherah)
const LEVEL_TO_NUMBER = {
  trace: -1,
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

// Wrap setup to normalize config
function setup(config) {
  return native.setup(normalizeConfig(config));
}

function setupAsync(config) {
  return native.setupAsync(normalizeConfig(config));
}

// set_log_hook: accept canonical (level, message) callback or native (event) callback
function set_log_hook(callback) {
  if (callback == null) {
    return native.setLogHook(null);
  }
  // Canonical callback: (level: number, message: string) => void (arity 2)
  // Native callback: (event: {level, message, target}) => void (arity 1)
  if (callback.length >= 2) {
    return native.setLogHook(function (event) {
      const numLevel =
        LEVEL_TO_NUMBER[event.level] !== undefined
          ? LEVEL_TO_NUMBER[event.level]
          : 1;
      callback(numLevel, event.message);
    });
  }
  return native.setLogHook(callback);
}

// Export everything from native addon
Object.assign(module.exports, native);

// Override setup/setupAsync with normalizing versions
module.exports.setup = setup;
module.exports.setupAsync = setupAsync;

// snake_case aliases for canonical API compatibility
module.exports.setup_async = setupAsync;
module.exports.shutdown_async = native.shutdownAsync;
module.exports.encrypt_async = native.encryptAsync;
module.exports.encrypt_string = native.encryptString;
module.exports.encrypt_string_async = native.encryptStringAsync;
module.exports.decrypt_async = native.decryptAsync;
module.exports.decrypt_string = native.decryptString;
module.exports.decrypt_string_async = native.decryptStringAsync;
module.exports.set_max_stack_alloc_item_size = native.setMaxStackAllocItemSize;
module.exports.set_safety_padding_overhead = native.setSafetyPaddingOverhead;
module.exports.set_log_hook = set_log_hook;
module.exports.get_setup_status = native.getSetupStatus;
