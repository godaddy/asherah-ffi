<?php

declare(strict_types=1);

namespace GoDaddy\Asherah;

use FFI;
use FFI\CData;

final class Session
{
    private ?CData $handle;

    public function __construct(?CData $handle)
    {
        if ($handle === null || FFI::isNull($handle)) {
            throw new AsherahException('get_session failed: ' . Native::lastError());
        }
        $this->handle = $handle;
    }

    public function encryptBytes(string $payload): string
    {
        $this->assertOpen();
        $input = Native::bytes($payload);
        $out = Native::newOutputBuffer();
        $rc = Native::ffi()->asherah_encrypt_to_json($this->handle, $input, strlen($payload), FFI::addr($out));
        if ($rc !== 0) {
            throw new AsherahException('encrypt failed: ' . Native::lastError());
        }

        return Native::readAndFree($out);
    }

    public function decryptBytes(string $dataRowRecord): string
    {
        $this->assertOpen();
        $input = Native::bytes($dataRowRecord);
        $out = Native::newOutputBuffer();
        $rc = Native::ffi()->asherah_decrypt_from_json($this->handle, $input, strlen($dataRowRecord), FFI::addr($out));
        if ($rc !== 0) {
            throw new AsherahException('decrypt failed: ' . Native::lastError());
        }

        return Native::readAndFree($out);
    }

    public function close(): void
    {
        if ($this->handle === null) {
            return;
        }

        Native::ffi()->asherah_session_free($this->handle);
        $this->handle = null;
    }

    public function __destruct()
    {
        $this->close();
    }

    private function assertOpen(): void
    {
        if ($this->handle === null) {
            throw new AsherahException('session is closed');
        }
    }
}
