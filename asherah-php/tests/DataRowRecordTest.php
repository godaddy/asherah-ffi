<?php

declare(strict_types=1);

namespace GoDaddy\Asherah\Tests;

use GoDaddy\Asherah\DataRowRecord;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class DataRowRecordTest extends TestCase
{
    public function testFromJsonValidDRR(): void
    {
        $json = '{"Data":"dGVzdA==","Key":{"Created":1234567890,"Key":"YWJjZGVm","ParentKeyMeta":{"KeyId":"parent-key-123","Created":1234567800}}}';
        $drr = DataRowRecord::fromJson($json);

        $this->assertSame($json, $drr->toJson());
        $this->assertSame($json, (string) $drr);
    }

    public function testFromJsonMinimalDRR(): void
    {
        $json = '{"Data":"dGVzdA=="}';
        $drr = DataRowRecord::fromJson($json);

        $this->assertSame($json, $drr->toJson());
        $this->assertFalse($drr->hasKey());
    }

    public function testFromJsonEmptyStringFails(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid DataRowRecord JSON');
        DataRowRecord::fromJson('');
    }

    public function testFromJsonInvalidJsonFails(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid DataRowRecord JSON');
        DataRowRecord::fromJson('{not valid json}');
    }

    public function testFromJsonNotAnObjectFails(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('DataRowRecord must be a JSON object');
        DataRowRecord::fromJson('[]');
    }

    public function testFromJsonMissingDataFieldFails(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("DataRowRecord missing required 'Data' field");
        DataRowRecord::fromJson('{"Key":{"Created":123}}');
    }

    public function testHasKey(): void
    {
        $withKey = DataRowRecord::fromJson('{"Data":"dGVzdA==","Key":{"Created":123,"Key":"YWJj"}}');
        $withoutKey = DataRowRecord::fromJson('{"Data":"dGVzdA=="}');

        $this->assertTrue($withKey->hasKey());
        $this->assertFalse($withoutKey->hasKey());
    }

    public function testGetKeyCreated(): void
    {
        $drr = DataRowRecord::fromJson('{"Data":"dGVzdA==","Key":{"Created":1234567890,"Key":"YWJj"}}');
        $this->assertSame(1234567890, $drr->getKeyCreated());

        $noKey = DataRowRecord::fromJson('{"Data":"dGVzdA=="}');
        $this->assertNull($noKey->getKeyCreated());
    }

    public function testGetParentKeyId(): void
    {
        $drr = DataRowRecord::fromJson('{"Data":"dGVzdA==","Key":{"Created":123,"Key":"YWJj","ParentKeyMeta":{"KeyId":"parent-123","Created":100}}}');
        $this->assertSame('parent-123', $drr->getParentKeyId());

        $noParent = DataRowRecord::fromJson('{"Data":"dGVzdA==","Key":{"Created":123,"Key":"YWJj"}}');
        $this->assertNull($noParent->getParentKeyId());

        $noKey = DataRowRecord::fromJson('{"Data":"dGVzdA=="}');
        $this->assertNull($noKey->getParentKeyId());
    }

    public function testGetParentKeyCreated(): void
    {
        $drr = DataRowRecord::fromJson('{"Data":"dGVzdA==","Key":{"Created":123,"Key":"YWJj","ParentKeyMeta":{"KeyId":"parent-123","Created":100}}}');
        $this->assertSame(100, $drr->getParentKeyCreated());

        $noParent = DataRowRecord::fromJson('{"Data":"dGVzdA==","Key":{"Created":123,"Key":"YWJj"}}');
        $this->assertNull($noParent->getParentKeyCreated());
    }

    public function testToStringConversion(): void
    {
        $json = '{"Data":"dGVzdA==","Key":{"Created":123,"Key":"YWJj"}}';
        $drr = DataRowRecord::fromJson($json);

        $this->assertSame($json, $drr->toJson());
        $this->assertSame($json, (string) $drr);
    }
}
