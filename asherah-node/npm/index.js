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

let native = null;
let lastErr = null;
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
  throw new Error(`Failed to load Asherah native addon for ${platform}${detail}`);
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
  ReplicaReadConsistency: 'replicaReadConsistency',
  Verbose: 'verbose',
};

// Fields from canonical API that we silently ignore (Go-specific)
const IGNORED_FIELDS = new Set([
  'DisableZeroCopy',
  'EnableCanaries',
]);

// Metastore value normalization (canonical test values → ours)
const METASTORE_MAP = {
  'test-debug-memory': 'memory',
  'test-debug-static': 'static',
};

// KMS value normalization
const KMS_MAP = {
  'test-debug-static': 'static',
};

function normalizeConfig(config) {
  // Detect PascalCase format by checking for capital-S ServiceName
  if (!config || typeof config.ServiceName !== 'string') {
    return config;
  }

  const normalized = {};
  for (const [key, value] of Object.entries(config)) {
    if (IGNORED_FIELDS.has(key)) continue;
    const camelKey = CONFIG_MAP[key];
    if (camelKey) {
      normalized[camelKey] = value;
    } else {
      // Pass through unknown fields as-is
      normalized[key] = value;
    }
  }

  // Normalize metastore values
  if (normalized.metastore && METASTORE_MAP[normalized.metastore]) {
    normalized.metastore = METASTORE_MAP[normalized.metastore];
  }

  // Normalize KMS values
  if (normalized.kms && KMS_MAP[normalized.kms]) {
    normalized.kms = KMS_MAP[normalized.kms];
  }

  return normalized;
}

// Log level mapping: our string levels → zerolog numeric levels (used by canonical Go asherah)
const LOG_LEVEL_MAP = {
  trace: -1,
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function wrapLogHook(callback) {
  // Canonical callback signature: (level: number, message: string) => void
  // Ours: (event: {level: string, message: string, target: string}) => void
  // Detect arity-2 callbacks and wrap them
  if (callback && callback.length === 2) {
    return function (event) {
      const numLevel = LOG_LEVEL_MAP[event.level] !== undefined ? LOG_LEVEL_MAP[event.level] : 1;
      callback(numLevel, event.message);
    };
  }
  return callback;
}

// Build the wrapped module
const wrapped = Object.assign({}, native);

// Wrap setup to normalize config
wrapped.setup = function setup(config) {
  return native.setup(normalizeConfig(config));
};

wrapped.setupAsync = function setupAsync(config) {
  return native.setupAsync(normalizeConfig(config));
};

// Snake_case function aliases
wrapped.setup_async = function setup_async(config) {
  return native.setupAsync(normalizeConfig(config));
};

wrapped.shutdown_async = function shutdown_async() {
  return native.shutdownAsync();
};

wrapped.encrypt_async = function encrypt_async(partitionId, data) {
  return native.encryptAsync(partitionId, data);
};

wrapped.encrypt_string = function encrypt_string(partitionId, data) {
  return native.encryptString(partitionId, data);
};

wrapped.encrypt_string_async = function encrypt_string_async(partitionId, data) {
  return native.encryptStringAsync(partitionId, data);
};

wrapped.decrypt_async = function decrypt_async(partitionId, dataRowRecordJson) {
  return native.decryptAsync(partitionId, dataRowRecordJson);
};

wrapped.decrypt_string = function decrypt_string(partitionId, dataRowRecordJson) {
  return native.decryptString(partitionId, dataRowRecordJson);
};

wrapped.decrypt_string_async = function decrypt_string_async(partitionId, dataRowRecordJson) {
  return native.decryptStringAsync(partitionId, dataRowRecordJson);
};

wrapped.set_max_stack_alloc_item_size = function set_max_stack_alloc_item_size(n) {
  return native.setMaxStackAllocItemSize(n);
};

wrapped.set_safety_padding_overhead = function set_safety_padding_overhead(n) {
  return native.setSafetyPaddingOverhead(n);
};

wrapped.set_log_hook = function set_log_hook(callback) {
  return native.setLogHook(callback ? wrapLogHook(callback) : callback);
};

wrapped.get_setup_status = function get_setup_status() {
  return native.getSetupStatus();
};

module.exports = wrapped;
