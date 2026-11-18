<?php

namespace Qaify\Sentinel;

/**
 * Pengganti data pribadi sebelum keluar dari server aplikasi:
 * - ip_hash: HMAC-SHA256(token, ip) — bisa dihitung unik, tidak bisa dibalik tanpa token;
 * - ip_prefix: alamat jaringan /24 (IPv4) atau /48 (IPv6), hanya untuk geolokasi (Qaify membuangnya setelah lookup);
 * - subject_hash: HMAC username login / id admin.
 */
final class Privacy
{
    public function __construct(private readonly string $key) {}

    public function hash(?string $value): ?string
    {
        return $value === null || $value === '' ? null : hash_hmac('sha256', strtolower(trim($value)), $this->key);
    }

    public static function prefix(?string $ip): ?string
    {
        if (! $ip || ! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return null;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);

            return "{$parts[0]}.{$parts[1]}.{$parts[2]}.0/24";
        }
        $packed = inet_pton($ip);
        if ($packed === false) {
            return null;
        }

        return inet_ntop(substr($packed, 0, 6) . str_repeat("\0", 10)) . '/48';
    }
}
