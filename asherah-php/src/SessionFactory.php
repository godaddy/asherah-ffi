<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

use FFI;
use FFI\CData;

/**
 * @phpstan-import-type AsherahConfigArray from Asherah
 */
final class SessionFactory
{
    private ?CData $handle;

    /**
     * @param AsherahConfigArray|AsherahConfig $config
     */
    public static function fromConfig(array|AsherahConfig $config): self
    {
        $config = ConfigValidator::normalize($config);
        try {
            $json = json_encode($config, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ConfigurationException('config must be JSON serializable: ' . $e->getMessage(), previous: $e);
        }
        $handle = Native::ffi()->asherah_factory_new_with_config($json);
        return new self($handle, 'factory creation failed');
    }

    public static function fromEnv(): self
    {
        $handle = Native::ffi()->asherah_factory_new_from_env();
        return new self($handle, 'factory_from_env failed');
    }

    private function __construct(?CData $handle, string $message)
    {
        if ($handle === null || FFI::isNull($handle)) {
            throw new NativeOperationException($message . ': ' . Native::lastError());
        }
        $this->handle = $handle;
    }

    public function getSession(string $partitionId): Session
    {
        if ($partitionId === '') {
            throw new \InvalidArgumentException('partition_id cannot be empty');
        }
        $this->assertOpen();

        $handle = Native::ffi()->asherah_factory_get_session($this->handle, $partitionId);
        return new Session($handle);
    }

    public function close(): void
    {
        if ($this->handle === null) {
            return;
        }

        Native::ffi()->asherah_factory_free($this->handle);
        $this->handle = null;
    }

    public function __destruct()
    {
        $this->close();
    }

    private function assertOpen(): void
    {
        if ($this->handle === null) {
            throw new LifecycleException('factory is closed');
        }
    }
}
