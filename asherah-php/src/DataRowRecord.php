<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

use JsonException;

/**
 * @phpstan-type ParsedDRR array{Data: string, Key?: array{Created: int, Key?: string, ParentKeyMeta?: array{KeyId: string, Created: int}}}
 */
final class DataRowRecord
{
    /**
     * @param array<string, mixed>|null $parsed
     */
    private function __construct(
        private readonly string $json,
        private readonly ?array $parsed = null
    ) {
    }

    public static function fromJson(string $json): self
    {
        try {
            $parsed = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new \InvalidArgumentException("Invalid DataRowRecord JSON: " . $e->getMessage(), 0, $e);
        }

        if (!is_array($parsed) || array_is_list($parsed)) {
            throw new \InvalidArgumentException("DataRowRecord must be a JSON object");
        }

        if (!isset($parsed['Data']) || !is_string($parsed['Data'])) {
            throw new \InvalidArgumentException("DataRowRecord missing required 'Data' field");
        }

        return new self($json, $parsed);
    }

    public function toJson(): string
    {
        return $this->json;
    }

    public function __toString(): string
    {
        return $this->json;
    }

    public function hasKey(): bool
    {
        return isset($this->parsed()['Key']);
    }

    public function getKeyCreated(): ?int
    {
        $key = $this->parsed()['Key'] ?? null;
        if (!is_array($key)) {
            return null;
        }
        return $key['Created'] ?? null;
    }

    public function getParentKeyId(): ?string
    {
        $key = $this->parsed()['Key'] ?? null;
        if (!is_array($key)) {
            return null;
        }
        $parent = $key['ParentKeyMeta'] ?? null;
        if (!is_array($parent)) {
            return null;
        }
        return $parent['KeyId'] ?? null;
    }

    public function getParentKeyCreated(): ?int
    {
        $key = $this->parsed()['Key'] ?? null;
        if (!is_array($key)) {
            return null;
        }
        $parent = $key['ParentKeyMeta'] ?? null;
        if (!is_array($parent)) {
            return null;
        }
        return $parent['Created'] ?? null;
    }

    /**
     * @return array<string, mixed>
     */
    private function parsed(): array
    {
        if ($this->parsed !== null) {
            return $this->parsed;
        }

        try {
            $parsed = json_decode($this->json, true, flags: JSON_THROW_ON_ERROR);
            return is_array($parsed) ? $parsed : [];
        } catch (JsonException) {
            return [];
        }
    }
}
