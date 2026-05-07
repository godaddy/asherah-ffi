<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

final class KmsConfig
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

    public static function testDebugStatic(): self
    {
        return new self(['KMS' => 'test-debug-static']);
    }

    public static function static(string $staticMasterKeyHex): self
    {
        AsherahConfig::requireNonEmpty($staticMasterKeyHex, 'StaticMasterKeyHex');

        return new self([
            'KMS' => 'static',
            'StaticMasterKeyHex' => $staticMasterKeyHex,
        ]);
    }

    /**
     * @param array<string, string> $regionMap
     */
    public static function aws(
        ?array $regionMap = null,
        ?string $preferredRegion = null,
        ?string $kmsKeyId = null
    ): self {
        $values = ['KMS' => 'aws'];

        if ($regionMap !== null) {
            if ($regionMap === []) {
                throw new ConfigurationException('RegionMap must contain at least one entry');
            }
            foreach ($regionMap as $mapRegion => $keyArn) {
                AsherahConfig::requireNonEmpty((string) $mapRegion, 'RegionMap region');
                AsherahConfig::requireNonEmpty($keyArn, "RegionMap entry for {$mapRegion}");
            }
            $values['RegionMap'] = $regionMap;
        }

        if ($preferredRegion !== null) {
            AsherahConfig::requireNonEmpty($preferredRegion, 'PreferredRegion');
            $values['PreferredRegion'] = $preferredRegion;
        }

        if ($kmsKeyId !== null) {
            AsherahConfig::requireNonEmpty($kmsKeyId, 'KmsKeyId');
            $values['KmsKeyId'] = $kmsKeyId;
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
