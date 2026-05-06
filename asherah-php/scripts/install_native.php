#!/usr/bin/env php
<?php

declare(strict_types=1);

use GoDaddy\Asherah\NativeLibraryInstaller;

require_once dirname(__DIR__) . '/vendor/autoload.php';

exit((new NativeLibraryInstaller())->run(array_slice($argv, 1)));
