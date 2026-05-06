<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

final class Asherah
{
    private static ?SessionFactory $factory = null;
    /** @var array<string, Session> */
    private static array $sessions = [];
    private static int $sessionCacheMaxSize = 1000;
    private static bool $sessionCacheEnabled = true;

    /**
     * @param array<string, mixed> $config
     */
    public static function setup(array $config): void
    {
        if (self::$factory !== null) {
            throw new AsherahException('already initialized');
        }

        foreach (['ServiceName', 'ProductID', 'Metastore'] as $key) {
            if (!isset($config[$key]) || trim((string) $config[$key]) === '') {
                throw new \InvalidArgumentException("$key is required");
            }
        }

        self::$sessionCacheEnabled = ($config['EnableSessionCaching'] ?? true) !== false;
        self::$sessionCacheMaxSize = max(1, (int) ($config['SessionCacheMaxSize'] ?? 1000));
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
            throw new AsherahException('not initialized');
        }

        return self::$factory->getSession($partitionId);
    }
}
