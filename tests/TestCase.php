<?php

namespace Qaify\Sentinel\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Qaify\Sentinel\SentinelServiceProvider;

abstract class TestCase extends Orchestra
{
    protected string $bufferDir;

    protected function getPackageProviders($app): array
    {
        return [SentinelServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $this->bufferDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qaify-sentinel-test-' . bin2hex(random_bytes(4));
        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('sentinel.url', 'https://qaify.test');
        $app['config']->set('sentinel.token', 'qsn_test_token');
        $app['config']->set('sentinel.buffer_path', $this->bufferDir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->bufferDir . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            @unlink($file);
        }
        @unlink($this->bufferDir . DIRECTORY_SEPARATOR . '.heartbeat');
        @rmdir($this->bufferDir);
        parent::tearDown();
    }

    /** @return list<array> baris buffer semua berkas */
    protected function bufferLines(): array
    {
        $lines = [];
        foreach (glob($this->bufferDir . DIRECTORY_SEPARATOR . '*.jsonl') ?: [] as $file) {
            foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $lines[] = json_decode($line, true);
            }
        }

        return $lines;
    }
}
