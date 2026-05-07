<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

/**
 * @phpstan-import-type AsherahConfigArray from Asherah
 */
final class ConfigValidator
{
    /**
     * @param AsherahConfigArray|AsherahConfig $config
     * @return AsherahConfigArray
     */
    public static function normalize(array|AsherahConfig $config): array
    {
        $config = $config instanceof AsherahConfig ? $config->toArray() : $config;

        foreach (['ServiceName', 'ProductID', 'Metastore', 'KMS'] as $key) {
            self::requireString($config, $key);
        }

        foreach ([
            'ConnectionString',
            'SQLMetastoreDBType',
            'ReplicaReadConsistency',
            'DynamoDBTableName',
            'DynamoDBRegion',
            'DynamoDBSigningRegion',
            'DynamoDBEndpoint',
            'PreferredRegion',
            'KmsKeyId',
            'StaticMasterKeyHex',
            'AwsProfileName',
        ] as $key) {
            self::optionalString($config, $key);
        }

        self::optionalBool($config, 'EnableSessionCaching');
        self::optionalBool($config, 'EnableRegionSuffix');
        self::optionalInt($config, 'SessionCacheMaxSize', 1);
        self::optionalInt($config, 'SessionCacheDuration', 0);
        self::optionalInt($config, 'ExpireAfter', 1);
        self::optionalInt($config, 'CheckInterval', 1);
        self::optionalRegionMap($config);

        return $config;
    }

    /**
     * @param array<string, mixed> $config
     */
    public static function sessionCacheEnabled(array $config): bool
    {
        if (!array_key_exists('EnableSessionCaching', $config)) {
            return true;
        }

        return $config['EnableSessionCaching'];
    }

    /**
     * @param array<string, mixed> $config
     */
    public static function sessionCacheMaxSize(array $config): int
    {
        if (!array_key_exists('SessionCacheMaxSize', $config)) {
            return 1000;
        }

        return $config['SessionCacheMaxSize'];
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function requireString(array $config, string $key): void
    {
        if (!array_key_exists($key, $config) || !is_string($config[$key]) || trim($config[$key]) === '') {
            throw new ConfigurationException("{$key} is required");
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function optionalString(array $config, string $key): void
    {
        if (!array_key_exists($key, $config)) {
            return;
        }
        if (!is_string($config[$key]) || trim($config[$key]) === '') {
            throw new ConfigurationException("{$key} must be a non-empty string");
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function optionalBool(array $config, string $key): void
    {
        if (!array_key_exists($key, $config)) {
            return;
        }
        if (!is_bool($config[$key])) {
            throw new ConfigurationException("{$key} must be boolean");
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function optionalInt(array $config, string $key, int $minimum): void
    {
        if (!array_key_exists($key, $config)) {
            return;
        }
        if (!is_int($config[$key]) || $config[$key] < $minimum) {
            throw new ConfigurationException("{$key} must be an integer >= {$minimum}");
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    private static function optionalRegionMap(array $config): void
    {
        if (!array_key_exists('RegionMap', $config)) {
            return;
        }
        if (!is_array($config['RegionMap']) || $config['RegionMap'] === []) {
            throw new ConfigurationException('RegionMap must contain at least one entry');
        }

        foreach ($config['RegionMap'] as $region => $keyArn) {
            if (!is_string($region) || trim($region) === '') {
                throw new ConfigurationException('RegionMap regions must be non-empty strings');
            }
            if (!is_string($keyArn) || trim($keyArn) === '') {
                throw new ConfigurationException("RegionMap entry for {$region} must be a non-empty string");
            }
        }
    }
}
