<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

use JsonSerializable;

/**
 * @phpstan-type AsherahConfigArray array{
 *   ServiceName: string,
 *   ProductID: string,
 *   Metastore: string,
 *   KMS: string,
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
final class AsherahConfig implements JsonSerializable
{
    private string $serviceName;
    private string $productId;
    private MetastoreConfig $metastore;
    private KmsConfig $kms;

    /** @var array<string, mixed> */
    private array $options = [];

    public function __construct(
        string $serviceName,
        string $productId,
        MetastoreConfig $metastore,
        KmsConfig $kms
    ) {
        self::requireNonEmpty($serviceName, 'ServiceName');
        self::requireNonEmpty($productId, 'ProductID');

        $this->serviceName = $serviceName;
        $this->productId = $productId;
        $this->metastore = $metastore;
        $this->kms = $kms;
    }

    public static function memoryTestDebugStatic(string $serviceName, string $productId): self
    {
        return new self(
            $serviceName,
            $productId,
            MetastoreConfig::memory(),
            KmsConfig::testDebugStatic()
        );
    }

    public function withExpireAfter(int $seconds): self
    {
        return $this->withOption('ExpireAfter', $seconds);
    }

    public function withCheckInterval(int $seconds): self
    {
        return $this->withOption('CheckInterval', $seconds);
    }

    public function withSessionCache(bool $enabled, ?int $maxSize = null, ?int $durationSeconds = null): self
    {
        $next = $this->withOption('EnableSessionCaching', $enabled);
        if ($maxSize !== null) {
            if ($maxSize < 1) {
                throw new ConfigurationException('SessionCacheMaxSize must be >= 1');
            }
            $next = $next->withOption('SessionCacheMaxSize', $maxSize);
        }
        if ($durationSeconds !== null) {
            $next = $next->withOption('SessionCacheDuration', $durationSeconds);
        }

        return $next;
    }

    public function withAwsProfileName(?string $profileName): self
    {
        if ($profileName === null || $profileName === '') {
            return $this->withoutOption('AwsProfileName');
        }

        return $this->withOption('AwsProfileName', $profileName);
    }

    /**
     * @param scalar|array<string, mixed>|null $value
     */
    public function withOption(string $key, mixed $value): self
    {
        self::requireNonEmpty($key, 'config option key');
        $next = clone $this;
        $next->options[$key] = $value;
        return $next;
    }

    public function withoutOption(string $key): self
    {
        $next = clone $this;
        unset($next->options[$key]);
        return $next;
    }

    /**
     * @return AsherahConfigArray
     */
    public function toArray(): array
    {
        return array_replace(
            [
                'ServiceName' => $this->serviceName,
                'ProductID' => $this->productId,
            ],
            $this->metastore->toArray(),
            $this->kms->toArray(),
            $this->options
        );
    }

    /**
     * @return AsherahConfigArray
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    public static function requireNonEmpty(string $value, string $field): void
    {
        if (trim($value) === '') {
            throw new ConfigurationException("{$field} is required");
        }
    }
}
