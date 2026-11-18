<?php

namespace Qaify\Sentinel;

/**
 * Menggolongkan satu request/respons. Hanya path + query yang diperiksa (body tidak dibaca); yang dikirim ke Qaify
 * hanya id aturan, bukan teks yang cocok. Urutan: login gagal → payload → probe berkas → pemindai → status.
 */
final class Classifier
{
    /** id aturan → [regex, severity dasar] — diperiksa pada path+query yang sudah di-decode */
    public const PAYLOADS = [
        'log4shell'      => ['/\$\{\s*jndi\s*:/i', 'high'],
        'rce.shell'      => ['/(;|\||&&|`|\$\()\s*(cat|wget|curl|bash|sh|nc|id|whoami|uname|powershell)\b/i', 'high'],
        'sqli.union'     => ['/\bunion(\s|\+|\/\*.*?\*\/)+(all(\s|\+)+)?select\b/i', 'medium'],
        'sqli.time'      => ['/\b(sleep|pg_sleep|benchmark)\s*\(\s*\d|waitfor\s+delay\s+\'/i', 'medium'],
        'sqli.boolean'   => ['/(\'|")\s*(or|and)\s*(\'|"|\d)[^&]{0,20}(=|like)|\bor\s+1\s*=\s*1\b|\'\s*--\s*$/i', 'medium'],
        'sqli.stacked'   => ['/;\s*(drop|truncate|insert\s+into|update\s+\w+\s+set|delete\s+from)\b/i', 'medium'],
        'xss.script'     => ['/<\s*script\b|<\s*\/\s*script\s*>/i', 'medium'],
        'xss.event'      => ['/<[^>]+\bon(error|load|mouseover|focus|click|toggle)\s*=/i', 'medium'],
        'xss.js_uri'     => ['/javascript\s*:\s*[a-z(]/i', 'medium'],
        'lfi.sensitive'  => ['/(\/etc\/(passwd|shadow|hosts)|\/proc\/self\/environ|c:\\\\windows\\\\win\.ini|boot\.ini)/i', 'medium'],
        'path.traversal' => ['/(\.\.\/){2,}|(\.\.\\\\){2,}/', 'medium'],
        'php.wrapper'    => ['/\b(php|phar|expect|data):\/\/(input|filter|stdin)?|base64_decode\s*\(|\beval\s*\(/i', 'medium'],
        'ssti'           => ['/\{\{\s*\d+\s*[*+]\s*\d+\s*\}\}|\$\{\s*\d+\s*[*+]\s*\d+\s*\}|\{\{\s*(config|self|request)\b/i', 'medium'],
    ];

    /** path sensitif yang biasa dipindai bot (tanpa / di depan) */
    public const PROBE_PATHS = [
        'path.env'       => '/(^|\/)\.env(\.\w+)?$/i',
        'path.git'       => '/(^|\/)\.(git|svn|hg)(\/|$)/i',
        'path.aws'       => '/(^|\/)\.aws\/credentials$/i',
        'path.wordpress' => '/(^|\/)(wp-admin|wp-login\.php|xmlrpc\.php|wp-content\/plugins)/i',
        'path.dbadmin'   => '/(^|\/)(phpmyadmin|pma|myadmin|adminer(\.php)?)(\/|$)/i',
        'path.phpunit'   => '/vendor\/phpunit\//i',
        'path.backup'    => '/\.(bak|old|orig|swp|sql|sql\.gz|tar\.gz|zip)$/i',
        'path.actuator'  => '/(^|\/)(actuator|server-status|server-info|_profiler|telescope)(\/|$)/i',
        'path.config'    => '/(^|\/)(config\.php|web\.config|composer\.(json|lock)|docker-compose\.ya?ml|\.htaccess|\.DS_Store)$/i',
        'path.shell'     => '/(^|\/)(shell|cmd|c99|r57|webshell)\.php$/i',
        'path.cgi'       => '/(^|\/)cgi-bin\//i',
    ];

    /** keluarga user-agent pemindai otomatis */
    public const AGENTS = [
        'qaify'    => '/qaify(scanner|monitor)/i',
        'sqlmap'   => '/sqlmap/i',
        'nikto'    => '/nikto/i',
        'nuclei'   => '/nuclei/i',
        'zgrab'    => '/zgrab/i',
        'masscan'  => '/masscan/i',
        'nmap'     => '/nmap/i',
        'gobuster' => '/gobuster/i',
        'dirbuster' => '/dirbuster/i',
        'ffuf'     => '/fuzz faster|ffuf/i',
        'wpscan'   => '/wpscan/i',
        'acunetix' => '/acunetix|wvs/i',
        'nessus'   => '/nessus/i',
        'openvas'  => '/openvas/i',
        'hydra'    => '/hydra/i',
        'zap'      => '/owasp[ _-]?zap|zaproxy/i',
    ];

    /**
     * @param string $path path tanpa query, boleh diawali "/"
     * @param string $query query string mentah (hanya dicocokkan, tidak pernah dikirim)
     */
    public function classify(string $method, string $path, string $query, int $status, ?string $userAgent, bool $isLogin, bool $statusEvents = true): ?Detection
    {
        $agent = self::agent($userAgent);

        if ($isLogin && $method === 'POST' && in_array($status, [401, 403, 429], true)) {
            return new Detection('auth_failed', $status === 429 ? 'login.locked' : 'login', $status === 429 ? 'medium' : 'low', $agent);
        }

        $haystack = self::decode(ltrim($path, '/') . ($query !== '' ? '?' . $query : ''));
        foreach (self::PAYLOADS as $rule => [$regex, $severity]) {
            if (preg_match($regex, $haystack) === 1) {
                // dijawab sukses: payload mungkin sampai ke logika aplikasi
                return new Detection('payload', $rule, $status < 400 ? 'high' : $severity, $agent);
            }
        }

        $cleanPath = ltrim(self::decode($path), '/');
        foreach (self::PROBE_PATHS as $rule => $regex) {
            if (preg_match($regex, $cleanPath) === 1) {
                // berkas sensitif benar-benar tersaji = terekspos
                return new Detection('probe_path', $rule, $status >= 200 && $status < 300 ? 'high' : 'low', $agent);
            }
        }

        if ($agent !== null) {
            return new Detection('scanner', "ua.{$agent}", 'medium', $agent);
        }

        if (! $statusEvents) {
            return null;
        }

        return match (true) {
            $status >= 500 => new Detection('server_error', "http.{$status}", 'low', null),
            $status === 401 => new Detection('unauthorized', 'http.401', 'low', null),
            $status === 403 => new Detection('forbidden', 'http.403', 'low', null),
            $status === 429 => new Detection('rate_limited', 'http.429', 'low', null),
            default => null,
        };
    }

    public static function agent(?string $userAgent): ?string
    {
        if (! $userAgent) {
            return null;
        }
        foreach (self::AGENTS as $family => $regex) {
            if (preg_match($regex, $userAgent) === 1) {
                return $family;
            }
        }

        return null;
    }

    /** URL-decode berulang (payload sering di-encode ganda), dibatasi 3 putaran. */
    private static function decode(string $value): string
    {
        for ($i = 0; $i < 3; $i++) {
            $next = rawurldecode(str_replace('+', ' ', $value));
            if ($next === $value) {
                break;
            }
            $value = $next;
        }

        return mb_substr($value, 0, 4096);
    }
}
