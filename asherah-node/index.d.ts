/// <reference types="node" />

export type AsherahConfig = {
  serviceName: string;
  productId: string;
  expireAfter?: number | null;
  checkInterval?: number | null;
  metastore: 'memory' | 'rdbms' | 'dynamodb';
  connectionString?: string | null;
  replicaReadConsistency?: string | null;
  dynamoDBEndpoint?: string | null;
  dynamoDBRegion?: string | null;
  dynamoDBTableName?: string | null;
  sessionCacheMaxSize?: number | null;
  sessionCacheDuration?: number | null;
  kms?: 'aws' | 'static' | null;
  regionMap?: Record<string, string> | null;
  preferredRegion?: string | null;
  enableRegionSuffix?: boolean | null;
  enableSessionCaching?: boolean | null;
  verbose?: boolean | null;
  sqlMetastoreDBType?: string | null;
  disableZeroCopy?: boolean | null;
  nullDataCheck?: boolean | null;
  enableCanaries?: boolean | null;
};

/** Canonical godaddy/asherah-node PascalCase config format */
export type AsherahConfigCompat = {
  readonly ServiceName: string;
  readonly ProductID: string;
  readonly ExpireAfter?: number | null;
  readonly CheckInterval?: number | null;
  readonly Metastore: 'memory' | 'rdbms' | 'dynamodb' | 'test-debug-memory';
  readonly ConnectionString?: string | null;
  readonly DynamoDBEndpoint?: string | null;
  readonly DynamoDBRegion?: string | null;
  readonly DynamoDBTableName?: string | null;
  readonly SessionCacheMaxSize?: number | null;
  readonly SessionCacheDuration?: number | null;
  readonly KMS?: 'aws' | 'static' | 'test-debug-static' | null;
  readonly RegionMap?: Record<string, string> | null;
  readonly PreferredRegion?: string | null;
  readonly EnableRegionSuffix?: boolean | null;
  readonly EnableSessionCaching?: boolean | null;
  readonly Verbose?: boolean | null;
  readonly SQLMetastoreDBType?: string | null;
  readonly ReplicaReadConsistency?: 'eventual' | 'global' | 'session' | null;
  readonly DisableZeroCopy?: boolean | null;
  readonly NullDataCheck?: boolean | null;
  readonly EnableCanaries?: boolean | null;
};

/** Canonical godaddy/asherah-node log hook callback: (level: number, message: string) => void */
export type LogHookCallback = (level: number, message: string) => void;

export declare function setup(config: AsherahConfig | AsherahConfigCompat): void;
export declare function setupAsync(config: AsherahConfig | AsherahConfigCompat): Promise<void>;
export declare function shutdown(): void;
export declare function shutdownAsync(): Promise<void>;
export declare function getSetupStatus(): boolean;
export declare function setenv(env: string): void;

export declare function encrypt(partitionId: string, data: Buffer): string;
export declare function encryptAsync(partitionId: string, data: Buffer): Promise<string>;
export declare function decrypt(partitionId: string, dataRowRecordJson: string): Buffer;
export declare function decryptAsync(partitionId: string, dataRowRecordJson: string): Promise<Buffer>;

export declare function encryptString(partitionId: string, data: string): string;
export declare function encryptStringAsync(partitionId: string, data: string): Promise<string>;
export declare function decryptString(partitionId: string, dataRowRecordJson: string): string;
export declare function decryptStringAsync(partitionId: string, dataRowRecordJson: string): Promise<string>;

export declare function setMaxStackAllocItemSize(n: number): void;
export declare function setSafetyPaddingOverhead(n: number): void;

export type LogEvent = {
  level: 'trace' | 'debug' | 'info' | 'warn' | 'error';
  message: string;
  target: string;
};

export type MetricsEvent =
  | { type: 'encrypt' | 'decrypt' | 'store' | 'load'; durationNs: number }
  | { type: 'cache_hit' | 'cache_miss'; name: string };

export declare function setLogHook(hook: ((event: LogEvent) => void) | LogHookCallback | null): void;
export declare function setMetricsHook(hook: ((event: MetricsEvent) => void) | null): void;

// Canonical godaddy/asherah-node snake_case aliases
export declare function setup_async(config: AsherahConfig | AsherahConfigCompat): Promise<void>;
export declare function shutdown_async(): Promise<void>;
export declare function encrypt_async(partitionId: string, data: Buffer): Promise<string>;
export declare function encrypt_string(partitionId: string, data: string): string;
export declare function encrypt_string_async(partitionId: string, data: string): Promise<string>;
export declare function decrypt_async(partitionId: string, dataRowRecordJson: string): Promise<Buffer>;
export declare function decrypt_string(partitionId: string, dataRowRecordJson: string): string;
export declare function decrypt_string_async(partitionId: string, dataRowRecordJson: string): Promise<string>;
export declare function set_max_stack_alloc_item_size(n: number): void;
export declare function set_safety_padding_overhead(n: number): void;
export declare function set_log_hook(hook: ((event: LogEvent) => void) | LogHookCallback | null): void;
export declare function get_setup_status(): boolean;
