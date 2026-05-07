<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\Unit;

use GoDaddy\Asherah\AsherahConfig;
use GoDaddy\Asherah\KmsConfig;
use GoDaddy\Asherah\MetastoreConfig;
use PHPUnit\Framework\TestCase;

final class ConfigShapeTest extends TestCase
{
    public function testMemoryTestDebugStaticConfigShape(): void
    {
        $config = AsherahConfig::memoryTestDebugStatic('svc', 'prod')
            ->withSessionCache(true, 25, 7200)
            ->withExpireAfter(86400)
            ->withCheckInterval(3600);

        self::assertSame([
            'ServiceName' => 'svc',
            'ProductID' => 'prod',
            'Metastore' => 'memory',
            'KMS' => 'test-debug-static',
            'EnableSessionCaching' => true,
            'SessionCacheMaxSize' => 25,
            'SessionCacheDuration' => 7200,
            'ExpireAfter' => 86400,
            'CheckInterval' => 3600,
        ], $config->toArray());
    }

    public function testMultiRegionKmsConfigPreservesRegionMapAndPreferredRegion(): void
    {
        $regionMap = [
            'us-west-2' => 'arn:aws:kms:us-west-2:111122223333:key/west',
            'us-east-1' => 'arn:aws:kms:us-east-1:111122223333:key/east',
        ];
        $config = new AsherahConfig(
            'svc',
            'prod',
            MetastoreConfig::memory(),
            KmsConfig::aws(regionMap: $regionMap, preferredRegion: 'us-east-1')
        );

        self::assertSame($regionMap, $config->toArray()['RegionMap']);
        self::assertSame('us-east-1', $config->toArray()['PreferredRegion']);
        self::assertSame(
            '{"ServiceName":"svc","ProductID":"prod","Metastore":"memory","KMS":"aws","RegionMap":{"us-west-2":"arn:aws:kms:us-west-2:111122223333:key\/west","us-east-1":"arn:aws:kms:us-east-1:111122223333:key\/east"},"PreferredRegion":"us-east-1"}',
            json_encode($config, JSON_THROW_ON_ERROR)
        );
    }

    public function testSingleRegionKmsMapIsPreservedWithoutPhpSideRewrite(): void
    {
        $regionMap = ['us-west-2' => 'arn:aws:kms:us-west-2:111122223333:key/west'];
        $config = new AsherahConfig(
            'svc',
            'prod',
            MetastoreConfig::memory(),
            KmsConfig::aws(regionMap: $regionMap)
        );

        self::assertSame([
            'ServiceName' => 'svc',
            'ProductID' => 'prod',
            'Metastore' => 'memory',
            'KMS' => 'aws',
            'RegionMap' => $regionMap,
        ], $config->toArray());
    }

    public function testStaticKmsConfigShape(): void
    {
        $config = new AsherahConfig(
            'svc',
            'prod',
            MetastoreConfig::memory(),
            KmsConfig::static(str_repeat('a', 64))
        );

        self::assertSame([
            'ServiceName' => 'svc',
            'ProductID' => 'prod',
            'Metastore' => 'memory',
            'KMS' => 'static',
            'StaticMasterKeyHex' => str_repeat('a', 64),
        ], $config->toArray());
    }

    public function testSqliteMetastoreConfigShape(): void
    {
        $config = new AsherahConfig(
            'svc',
            'prod',
            MetastoreConfig::sqlite('sqlite:///tmp/asherah.db'),
            KmsConfig::testDebugStatic()
        );

        self::assertSame([
            'ServiceName' => 'svc',
            'ProductID' => 'prod',
            'Metastore' => 'sqlite',
            'ConnectionString' => 'sqlite:///tmp/asherah.db',
            'KMS' => 'test-debug-static',
        ], $config->toArray());
    }

    public function testRdbmsMetastoreConfigPreservesReplicaReadConsistency(): void
    {
        $config = new AsherahConfig(
            'svc',
            'prod',
            MetastoreConfig::rdbms(
                connectionString: 'postgres://user:pass@example.invalid/asherah',
                sqlMetastoreDbType: 'postgres',
                replicaReadConsistency: 'eventual'
            ),
            KmsConfig::testDebugStatic()
        );

        self::assertSame([
            'ServiceName' => 'svc',
            'ProductID' => 'prod',
            'Metastore' => 'rdbms',
            'ConnectionString' => 'postgres://user:pass@example.invalid/asherah',
            'SQLMetastoreDBType' => 'postgres',
            'ReplicaReadConsistency' => 'eventual',
            'KMS' => 'test-debug-static',
        ], $config->toArray());
    }

    public function testDynamoDbRegionSensitiveFieldsArePreserved(): void
    {
        $config = (new AsherahConfig(
            'svc',
            'prod',
            MetastoreConfig::dynamoDb(
                tableName: 'EncryptionKey',
                region: 'us-west-2',
                signingRegion: 'us-east-1',
                endpoint: 'https://dynamodb.us-west-2.amazonaws.com',
                enableRegionSuffix: true
            ),
            KmsConfig::aws(kmsKeyId: 'alias/asherah')
        ))->withAwsProfileName('prod-profile');

        self::assertSame([
            'ServiceName' => 'svc',
            'ProductID' => 'prod',
            'Metastore' => 'dynamodb',
            'DynamoDBTableName' => 'EncryptionKey',
            'DynamoDBRegion' => 'us-west-2',
            'DynamoDBSigningRegion' => 'us-east-1',
            'DynamoDBEndpoint' => 'https://dynamodb.us-west-2.amazonaws.com',
            'EnableRegionSuffix' => true,
            'KMS' => 'aws',
            'KmsKeyId' => 'alias/asherah',
            'AwsProfileName' => 'prod-profile',
        ], $config->toArray());
    }

    public function testAwsProfileNameIsExcludedWhenUnsetOrEmpty(): void
    {
        $config = (new AsherahConfig(
            'svc',
            'prod',
            MetastoreConfig::dynamoDb(region: 'us-west-2'),
            KmsConfig::aws(kmsKeyId: 'alias/asherah')
        ))->withAwsProfileName('')->withAwsProfileName(null);

        self::assertArrayNotHasKey('AwsProfileName', $config->toArray());
    }

    public function testTypedAndArrayConfigProduceEquivalentJson(): void
    {
        $typed = new AsherahConfig(
            'svc',
            'prod',
            MetastoreConfig::memory(),
            KmsConfig::testDebugStatic()
        );
        $array = [
            'ServiceName' => 'svc',
            'ProductID' => 'prod',
            'Metastore' => 'memory',
            'KMS' => 'test-debug-static',
        ];

        self::assertSame(
            json_encode($array, JSON_THROW_ON_ERROR),
            json_encode($typed, JSON_THROW_ON_ERROR)
        );
    }

    public function testUnknownOptionsArePreserved(): void
    {
        $config = AsherahConfig::memoryTestDebugStatic('svc', 'prod')
            ->withOption('FutureRustOption', ['enabled' => true]);

        /** @var array<string, mixed> $array */
        $array = $config->toArray();

        self::assertSame(['enabled' => true], $array['FutureRustOption']);
    }

    public function testEmptyRegionMapIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('RegionMap must contain at least one entry');

        KmsConfig::aws(regionMap: []);
    }
}
