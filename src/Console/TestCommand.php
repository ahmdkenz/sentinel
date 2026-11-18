<?php

namespace Qaify\Sentinel\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Qaify\Sentinel\Client;
use Qaify\Sentinel\Sentinel;
use Throwable;

/** sentinel:test — kirim satu kejadian uji ke Qaify; terlihat di SOC → Domain & Sensor ("terakhir terlihat"). */
final class TestCommand extends Command
{
    protected $signature = 'sentinel:test';

    protected $description = 'Uji koneksi sensor Sentinel ke Qaify SOC';

    public function handle(Client $client): int
    {
        if (! Sentinel::configured()) {
            $this->error('Isi QAIFY_SENTINEL_URL dan QAIFY_SENTINEL_TOKEN di .env, lalu php artisan config:clear.');

            return self::FAILURE;
        }

        try {
            $response = $client->send([
                'batch_id' => 'test-' . Str::random(20),
                'events'   => [['at' => gmdate('Y-m-d\TH:i:s\Z'), 'kind' => 'test', 'rule' => 'sentinel.test', 'severity' => 'low', 'count' => 1]],
            ]);
        } catch (Throwable $e) {
            $this->error('Qaify tidak terjangkau: ' . $e->getMessage());

            return self::FAILURE;
        }

        if ($response->successful()) {
            $this->info('Terhubung. Sensor Sentinel ' . Sentinel::VERSION . ' terlihat di Qaify SOC.');

            return self::SUCCESS;
        }
        $this->error("Qaify menjawab HTTP {$response->status()}: " . Str::limit((string) $response->json('message', $response->body()), 200));

        return self::FAILURE;
    }
}
