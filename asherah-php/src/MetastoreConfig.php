<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

final class MetastoreConfig
{
    /** @var array<string, mixed> */
    private array $values;

    /**
     * @param array<string, mixed> $values
     */
    private function __construct(array $values)
    {
        $this->values = $values;
    }

    public static function memory(): self
    {
        return new self(['Metastore' => 'memory']);
    }

    public static function sqlite(string $connectionString): self
    {
        AsherahConfig::requireNonEmpty($connectionString, 'ConnectionString');

        return new self([
            'Metastore' => 'sqlite',
            'ConnectionString' => $connectionString,
        ]);
    }

    public static function rdbms(
        string $connectionString,
        ?string $sqlMetastoreDbType = null,
        ?string $replicaReadConsistency = null
    ): self {
        AsherahConfig::requireNonEmpty($connectionString, 'ConnectionString');
        $values = [
            'Metastore' => 'rdbms',
            'ConnectionString' => $connectionString,
        ];

        if ($sqlMetastoreDbType !== null) {
            AsherahConfig::requireNonEmpty($sqlMetastoreDbType, 'SQLMetastoreDBType');
            $values['SQLMetastoreDBType'] = $sqlMetastoreDbType;
        }
        if ($replicaReadConsistency !== null) {
            AsherahConfig::requireNonEmpty($replicaReadConsistency, 'ReplicaReadConsistency');
            $values['ReplicaReadConsistency'] = $replicaReadConsistency;
        }

        return new self($values);
    }

    public static function dynamoDb(
        ?string $tableName = null,
        ?string $region = null,
        ?string $signingRegion = null,
        ?string $endpoint = null,
        bool $enableRegionSuffix = false
    ): self {
        $values = ['Metastore' => 'dynamodb'];

        if ($tableName !== null) {
            AsherahConfig::requireNonEmpty($tableName, 'DynamoDBTableName');
            $values['DynamoDBTableName'] = $tableName;
        }
        if ($region !== null) {
            AsherahConfig::requireNonEmpty($region, 'DynamoDBRegion');
            $values['DynamoDBRegion'] = $region;
        }
        if ($signingRegion !== null) {
            AsherahConfig::requireNonEmpty($signingRegion, 'DynamoDBSigningRegion');
            $values['DynamoDBSigningRegion'] = $signingRegion;
        }
        if ($endpoint !== null) {
            AsherahConfig::requireNonEmpty($endpoint, 'DynamoDBEndpoint');
            $values['DynamoDBEndpoint'] = $endpoint;
        }
        if ($enableRegionSuffix) {
            $values['EnableRegionSuffix'] = true;
        }

        return new self($values);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->values;
    }
}
