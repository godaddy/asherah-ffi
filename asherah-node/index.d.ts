/// <reference types="node" />

export type AsherahConfig = {
  serviceName: string;
  productId: string;
  expireAfter?: number | null;
  checkInterval?: number | null;
  metastore: 'memory' | 'rdbms' | 'dynamodb';
  connectionString?: string | null;
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
};

export declare function setup(config: AsherahConfig): void;
export declare function setupAsync(config: AsherahConfig): Promise<void>;
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

export declare function setLogHook(hook: ((event: LogEvent) => void) | null): void;
export declare function setMetricsHook(hook: ((event: MetricsEvent) => void) | null): void;
