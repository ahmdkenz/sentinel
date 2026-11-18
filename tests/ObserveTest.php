<?php

namespace Qaify\Sentinel\Tests;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Route;
use RuntimeException;

final class ObserveTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        Route::post('/api/v1/auth/login', fn () => response()->json(['message' => 'salah'], 401));
        Route::get('/api/items', fn () => ['ok' => true]);
        Route::get('/boom', fn () => throw new RuntimeException('x'));
        Route::get('/up', fn () => 'ok');
        Route::post('/api/admin/users', fn () => ['ok' => true]);
    }

    public function test_request_normal_hanya_penghitung(): void
    {
        $this->get('/api/items?page=2')->assertOk();

        $this->assertSame([['s' => 200]], $this->bufferLines());
    }

    public function test_login_gagal_tanpa_ip_mentah_maupun_username(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.77'])
            ->postJson('/api/v1/auth/login', ['username' => 'budi', 'password' => 'rahasia'])->assertUnauthorized();

        $line = $this->bufferLines()[0];
        $this->assertSame('auth_failed', $line['e']['kind']);
        $this->assertSame('203.0.113.0/24', $line['e']['ip_prefix']);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $line['e']['subject_hash']);
        $raw = json_encode($line);
        $this->assertStringNotContainsString('203.0.113.77', $raw);
        $this->assertStringNotContainsString('budi', $raw);
        $this->assertStringNotContainsString('rahasia', $raw);
    }

    public function test_payload_tanpa_query_terkirim(): void
    {
        $this->get('/api/items?id=1%20UNION%20SELECT%20password%20FROM%20users')->assertOk();

        $line = $this->bufferLines()[0];
        $this->assertSame('payload', $line['e']['kind']);
        $this->assertSame('high', $line['e']['severity']);
        $this->assertSame('/api/items', $line['e']['path']);
        $this->assertStringNotContainsString('password', json_encode($line));
    }

    public function test_error_aplikasi_dicatat_dan_sensor_tidak_mengganggu(): void
    {
        $this->get('/boom')->assertStatus(500);
        $this->assertSame('server_error', $this->bufferLines()[0]['e']['kind']);

        // buffer tidak bisa ditulis → request tetap normal
        config(['sentinel.buffer_path' => '/dev/null/tidak-bisa']);
        $this->app->forgetInstance(\Qaify\Sentinel\Buffer::class);
        $this->get('/api/items')->assertOk();
    }

    public function test_path_diabaikan_dan_sensor_mati_tanpa_token(): void
    {
        $this->get('/up')->assertOk();
        config(['sentinel.token' => null]);
        $this->get('/api/items?q=%3Cscript%3E')->assertOk();

        $this->assertSame([], $this->bufferLines());
    }

    public function test_admin_dari_ip_baru(): void
    {
        $admin = new class extends User {
            protected $guarded = [];
            public function hasRole($roles): bool { return in_array('ADMIN', (array) $roles, true); }
        };
        $admin->forceFill(['id' => 7]);

        $this->actingAs($admin)->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])->post('/api/admin/users')->assertOk();
        $this->actingAs($admin)->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])->post('/api/admin/users')->assertOk();
        $this->actingAs($admin)->withServerVariables(['REMOTE_ADDR' => '198.51.100.20'])->post('/api/admin/users')->assertOk();

        $events = array_values(array_filter(array_map(fn ($l) => $l['e'] ?? null, $this->bufferLines())));
        $this->assertCount(1, $events);
        $this->assertSame('admin_new_ip', $events[0]['kind']);
        $this->assertSame('198.51.100.0/24', $events[0]['ip_prefix']);
    }
}
