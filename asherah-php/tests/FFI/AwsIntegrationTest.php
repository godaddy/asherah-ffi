<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests\FFI;

use GoDaddy\Asherah\Asherah;
use GoDaddy\Asherah\AsherahConfig;
use GoDaddy\Asherah\KmsConfig;
use GoDaddy\Asherah\MetastoreConfig;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

final class AwsIntegrationTest extends TestCase
{
    protected function tearDown(): void
    {
        Asherah::shutdown();
    }

    public function testOptInMultiRegionKmsRoundTrip(): void
    {
        $regionMap = $this->regionMap();
        $preferredRegion = getenv('ASHERAH_PHP_AWS_KMS_PREFERRED_REGION') ?: null;

        Asherah::setup(new AsherahConfig(
            'php-aws-kms-service',
            'php-aws-kms-product',
            MetastoreConfig::memory(),
            KmsConfig::aws(regionMap: $regionMap, preferredRegion: $preferredRegion)
        ));

        $ciphertext = Asherah::encryptString('tenant-aws-kms', 'aws-kms-payload');

        self::assertSame('aws-kms-payload', Asherah::decryptString('tenant-aws-kms', $ciphertext));
    }

    public function testOptInDynamoDbRegionAndSigningRegionRoundTrip(): void
    {
        [$table, $region] = $this->dynamoDbTableAndRegion();

        $service = 'php-ddb-service-' . bin2hex(random_bytes(4));
        $product = 'php-ddb-product';

        Asherah::setup(new AsherahConfig(
            $service,
            $product,
            MetastoreConfig::dynamoDb(
                tableName: $table,
                region: $region,
                signingRegion: getenv('ASHERAH_PHP_AWS_DYNAMODB_SIGNING_REGION') ?: null,
                endpoint: getenv('ASHERAH_PHP_AWS_DYNAMODB_ENDPOINT') ?: null,
                enableRegionSuffix: $this->boolEnv('ASHERAH_PHP_AWS_DYNAMODB_ENABLE_REGION_SUFFIX')
            ),
            KmsConfig::testDebugStatic()
        ));

        $ciphertext = Asherah::encryptString('tenant-ddb', 'ddb-payload');

        self::assertSame('ddb-payload', Asherah::decryptString('tenant-ddb', $ciphertext));
    }

    public function testRequiredIntegrationModeFailsInsteadOfSkippingWhenKmsInputsAreMissing(): void
    {
        $restore = $this->setEnv([
            'ASHERAH_PHP_AWS_REQUIRE_INTEGRATION' => '1',
            'ASHERAH_PHP_AWS_KMS_REGION_MAP' => null,
        ]);

        try {
            $this->expectException(AssertionFailedError::class);
            $this->expectExceptionMessage('set ASHERAH_PHP_AWS_KMS_REGION_MAP JSON to run multi-region KMS integration');

            $this->regionMap();
        } finally {
            $restore();
        }
    }

    public function testRequiredIntegrationModeFailsInsteadOfSkippingWhenDynamoDbInputsAreMissing(): void
    {
        $restore = $this->setEnv([
            'ASHERAH_PHP_AWS_REQUIRE_INTEGRATION' => '1',
            'ASHERAH_PHP_AWS_DYNAMODB_TABLE' => null,
            'ASHERAH_PHP_AWS_DYNAMODB_REGION' => null,
        ]);

        try {
            $this->expectException(AssertionFailedError::class);
            $this->expectExceptionMessage(
                'set ASHERAH_PHP_AWS_DYNAMODB_TABLE and ASHERAH_PHP_AWS_DYNAMODB_REGION to run DynamoDB integration'
            );

            $this->dynamoDbTableAndRegion();
        } finally {
            $restore();
        }
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function dynamoDbTableAndRegion(): array
    {
        $table = getenv('ASHERAH_PHP_AWS_DYNAMODB_TABLE') ?: '';
        $region = getenv('ASHERAH_PHP_AWS_DYNAMODB_REGION') ?: '';
        if ($table === '' || $region === '') {
            $this->skipOrFail(
                'set ASHERAH_PHP_AWS_DYNAMODB_TABLE and ASHERAH_PHP_AWS_DYNAMODB_REGION to run DynamoDB integration'
            );
        }

        return [$table, $region];
    }

    /**
     * @return array<string, string>
     */
    private function regionMap(): array
    {
        $json = getenv('ASHERAH_PHP_AWS_KMS_REGION_MAP') ?: '';
        if ($json === '') {
            $this->skipOrFail('set ASHERAH_PHP_AWS_KMS_REGION_MAP JSON to run multi-region KMS integration');
        }

        $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded) || $decoded === []) {
            $this->skipOrFail('ASHERAH_PHP_AWS_KMS_REGION_MAP must be a non-empty JSON object');
        }

        $regionMap = [];
        foreach ($decoded as $region => $keyArn) {
            if (!is_string($region) || !is_string($keyArn) || $region === '' || $keyArn === '') {
                $this->skipOrFail('ASHERAH_PHP_AWS_KMS_REGION_MAP must map region strings to key ARN strings');
            }
            $regionMap[$region] = $keyArn;
        }

        return $regionMap;
    }

    private function skipOrFail(string $message): void
    {
        if ((getenv('ASHERAH_PHP_AWS_REQUIRE_INTEGRATION') ?: '') === '1') {
            self::fail($message);
        }

        self::markTestSkipped($message);
    }

    private function boolEnv(string $name): bool
    {
        $value = getenv($name);

        return $value === '1' || strtolower((string) $value) === 'true';
    }

    /**
     * @param array<string, ?string> $updates
     * @return callable(): void
     */
    private function setEnv(array $updates): callable
    {
        $previous = [];
        foreach ($updates as $name => $value) {
            $old = getenv($name);
            $previous[$name] = $old === false ? null : $old;
            putenv($value === null ? $name : "{$name}={$value}");
        }

        return static function () use ($previous): void {
            foreach ($previous as $name => $value) {
                putenv($value === null ? $name : "{$name}={$value}");
            }
        };
    }
}
