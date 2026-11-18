<?php

namespace Qaify\Sentinel\Tests;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Qaify\Sentinel\Buffer;

final class FlushTest extends TestCase
{
    private function seedMinute(int $minutesAgo, array $lines): string
    {
        $buffer = $this->app->make(Buffer::class);
        $time = time() - $minutesAgo * 60;
        foreach ($lines as [$status, $event]) {
            $buffer->append($status, $event, $time);
        }

        return $buffer->fileFor($time);
    }

    private function event(array $o = []): array
    {
        return ['kind' => 'payload', 'rule' => 'sqli.union', 'severity' => 'medium', 'method' => 'GET', 'path' => '/a', 'status' => 403, 'ip_hash' => str_repeat('a', 64), 'ip_prefix' => '203.0.113.0/24', ...$o];
    }

    public function test_menggabungkan_menit_tertutup_dan_menghapus_setelah_terkirim(): void
    {
        $closed = $this->seedMinute(2, [[200, null], [200, null], [403, $this->event()], [403, $this->event()], [500, $this->event(['kind' => 'server_error', 'rule' => 'http.500', 'severity' => 'low', 'status' => 500])]]);
        // menit berjalan (diberi +1 menit agar pergantian menit selama test tidak membuatnya tertutup)
        $current = $this->seedMinute(-1, [[200, null]]);
        Http::fake(['qaify.test/*' => Http::response(['data' => ['accepted' => 2]], 202)]);

        $this->artisan('sentinel:flush')->assertSuccessful();

        Http::assertSentCount(1);
        Http::assertSent(function (Request $r) {
            $this->assertSame('https://qaify.test/api/sentinel/batch', $r->url());
            $this->assertSame('Bearer qsn_test_token', $r->header('Authorization')[0]);
            $this->assertSame(['total' => 5, 's4xx' => 2, 's401' => 0, 's403' => 2, 's429' => 0, 's5xx' => 1], array_diff_key($r['traffic'][0], ['minute' => 1]));
            $this->assertCount(2, $r['events']);
            $this->assertSame('medium', $r['events'][0]['severity']);
            $this->assertSame(2, $r['events'][0]['count']);
            $this->assertSame('0.1.0', $r['sensor']['version']);

            return true;
        });
        $this->assertFileDoesNotExist($closed);
        $this->assertFileExists($current);
    }

    public function test_galat_server_menyimpan_berkas_dan_batch_id_tetap(): void
    {
        $file = $this->seedMinute(3, [[403, $this->event()]]);
        $ids = [];
        Http::fake(function (Request $r) use (&$ids) {
            $ids[] = $r['batch_id'];

            return Http::response([], count($ids) === 1 ? 503 : 202);
        });

        $this->artisan('sentinel:flush')->assertSuccessful();
        $this->assertFileExists($file);

        $this->artisan('sentinel:flush')->assertSuccessful();
        $this->assertFileDoesNotExist($file);
        $this->assertSame($ids[0], $ids[1]);
    }

    public function test_token_ditolak_berhenti_tanpa_menghapus(): void
    {
        $file = $this->seedMinute(2, [[200, null]]);
        Http::fake(['*' => Http::response(['message' => 'Invalid sentinel token'], 401)]);

        $this->artisan('sentinel:flush')->assertSuccessful();
        $this->assertFileExists($file);
    }

    public function test_berkas_terlalu_lama_dibuang(): void
    {
        $old = $this->seedMinute(26 * 60, [[200, null]]);
        Http::fake(['*' => Http::response([], 202)]);

        $this->artisan('sentinel:flush')->assertSuccessful();
        $this->assertFileDoesNotExist($old);
        Http::assertNothingSent();
    }

    public function test_sentinel_test_mengirim_kejadian_uji(): void
    {
        Http::fake(['*' => Http::response(['data' => ['accepted' => 1]], 202)]);

        $this->artisan('sentinel:test')->assertSuccessful();
        Http::assertSent(fn (Request $r) => $r['events'][0]['kind'] === 'test');
    }

    public function test_flush_terjadwal_tiap_menit(): void
    {
        $events = collect($this->app->make(\Illuminate\Console\Scheduling\Schedule::class)->events());

        $this->assertTrue($events->contains(fn ($e) => str_contains((string) $e->command, 'sentinel:flush') && $e->expression === '* * * * *'));
    }
}
