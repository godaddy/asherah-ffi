<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

/**
 * @phpstan-type AsherahConfigArray array{
 *   ServiceName?: string,
 *   ProductID?: string,
 *   Metastore?: string,
 *   KMS?: string,
 *   ConnectionString?: string,
 *   SQLMetastoreDBType?: string,
 *   ReplicaReadConsistency?: string,
 *   DynamoDBTableName?: string,
 *   DynamoDBRegion?: string,
 *   DynamoDBSigningRegion?: string,
 *   DynamoDBEndpoint?: string,
 *   EnableRegionSuffix?: bool,
 *   RegionMap?: array<string, string>,
 *   PreferredRegion?: string,
 *   KmsKeyId?: string,
 *   StaticMasterKeyHex?: string,
 *   AwsProfileName?: string,
 *   EnableSessionCaching?: bool,
 *   SessionCacheMaxSize?: int,
 *   SessionCacheDuration?: int,
 *   ExpireAfter?: int,
 *   CheckInterval?: int,
 *   ...<string, mixed>
 * }
 */
final class Asherah
{
    private static ?SessionFactory $factory = null;
    /** @var array<string, Session> */
    private static array $sessions = [];
    private static int $sessionCacheMaxSize = 1000;
    private static bool $sessionCacheEnabled = true;

    /**
     * @param AsherahConfigArray|AsherahConfig $config
     */
    public static function setup(array|AsherahConfig $config): void
    {
        if (self::$factory !== null) {
            throw new LifecycleException('already initialized');
        }

        $config = self::normalizeConfig($config);
        foreach (['ServiceName', 'ProductID', 'Metastore', 'KMS'] as $key) {
            if (!isset($config[$key]) || trim((string) $config[$key]) === '') {
                throw new ConfigurationException("$key is required");
            }
        }

        self::$sessionCacheEnabled = self::sessionCacheEnabled($config);
        self::$sessionCacheMaxSize = self::sessionCacheMaxSize($config);
        self::validateIntegerOption($config, 'SessionCacheDuration', 0);
        self::validateIntegerOption($config, 'ExpireAfter', 1);
        self::validateIntegerOption($config, 'CheckInterval', 1);
        self::$factory = SessionFactory::fromConfig($config);
        self::$sessions = [];
    }

    public static function shutdown(): void
    {
        foreach (self::$sessions as $session) {
            $session->close();
        }
        self::$sessions = [];
        self::$factory?->close();
        self::$factory = null;
    }

    public static function encrypt(string $partitionId, string $payload): string
    {
        if (!self::$sessionCacheEnabled) {
            $session = self::newSession($partitionId);
            try {
                return $session->encryptBytes($payload);
            } finally {
                $session->close();
            }
        }

        return self::cachedSession($partitionId)->encryptBytes($payload);
    }

    public static function encryptBytes(string $partitionId, string $payload): string
    {
        return self::encrypt($partitionId, $payload);
    }

    public static function decrypt(string $partitionId, string $dataRowRecord): string
    {
        if (!self::$sessionCacheEnabled) {
            $session = self::newSession($partitionId);
            try {
                return $session->decryptBytes($dataRowRecord);
            } finally {
                $session->close();
            }
        }

        return self::cachedSession($partitionId)->decryptBytes($dataRowRecord);
    }

    public static function decryptBytes(string $partitionId, string $dataRowRecord): string
    {
        return self::decrypt($partitionId, $dataRowRecord);
    }

    public static function encryptString(string $partitionId, string $payload): string
    {
        return self::encrypt($partitionId, $payload);
    }

    public static function decryptString(string $partitionId, string $dataRowRecord): string
    {
        return self::decrypt($partitionId, $dataRowRecord);
    }

    private static function cachedSession(string $partitionId): Session
    {
        if (isset(self::$sessions[$partitionId])) {
            $session = self::$sessions[$partitionId];
            unset(self::$sessions[$partitionId]);
            self::$sessions[$partitionId] = $session;
            return $session;
        }

        $session = self::newSession($partitionId);
        self::$sessions[$partitionId] = $session;
        if (count(self::$sessions) > self::$sessionCacheMaxSize) {
            $evicted = array_key_first(self::$sessions);
            if ($evicted !== null) {
                $old = self::$sessions[$evicted];
                unset(self::$sessions[$evicted]);
                $old->close();
            }
        }

        return $session;
    }

    private static function newSession(string $partitionId): Session
    {
        if ($partitionId === '') {
            throw new \InvalidArgumentException('partition_id cannot be empty');
        }
        if (self::$factory === null) {
            throw new LifecycleException('not initialized');
        }

        return self::$factory->getSession($partitionId);
    }

    /**
     * @param array<string, mixed>|AsherahConfig $config
     * @return array<string, mixed>
     */
    private static function normalizeConfig(array|AsherahConfig $config): array
    {
        return $config instanceof AsherahConfig ? $config->toArray() : $config;
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function sessionCacheEnabled(array $config): bool
    {
        if (!array_key_exists('EnableSessionCaching', $config)) {
            return true;
        }
        if (!is_bool($config['EnableSessionCaching'])) {
            throw new ConfigurationException('EnableSessionCaching must be boolean');
        }

        return $config['EnableSessionCaching'];
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function sessionCacheMaxSize(array $config): int
    {
        if (!array_key_exists('SessionCacheMaxSize', $config)) {
            return 1000;
        }
        if (!is_int($config['SessionCacheMaxSize']) || $config['SessionCacheMaxSize'] < 1) {
            throw new ConfigurationException('SessionCacheMaxSize must be an integer >= 1');
        }

        return $config['SessionCacheMaxSize'];
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function validateIntegerOption(array $config, string $key, int $minimum): void
    {
        if (!array_key_exists($key, $config)) {
            return;
        }
        if (!is_int($config[$key]) || $config[$key] < $minimum) {
            throw new ConfigurationException("{$key} must be an integer >= {$minimum}");
        }
    }
}
