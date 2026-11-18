<?php

namespace Qaify\Sentinel;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Throwable;

/**
 * Admin melakukan aksi (POST/PUT/PATCH/DELETE) dari IP yang belum terlihat 30 hari terakhir untuk akun itu.
 * Disimpan di cache aplikasi: hash IP (bukan IP) → waktu terakhir, maksimal 20 per akun.
 * IP pertama kali sejak sensor dipasang tidak dianggap baru (hindari alarm saat pemasangan).
 */
final class AdminTracker
{
    private const DAYS = 30;
    private const MAX = 20;

    public function isAdmin(Authenticatable $user): bool
    {
        try {
            $check = config('sentinel.admin_check');
            if (is_callable($check)) {
                return (bool) $check($user);
            }
            if (is_string($check) && str_contains($check, '@')) {
                [$class, $method] = explode('@', $check, 2);

                return (bool) app($class)->{$method}($user);
            }
            if (method_exists($user, 'hasRole')) {
                return (bool) $user->hasRole((array) config('sentinel.admin_roles', ['ADMIN']));
            }
        } catch (Throwable) {
            return false;
        }

        return false;
    }

    /** @return bool true bila IP ini baru untuk akun admin ini */
    public function seen(string $userKey, string $ipHash, ?int $now = null): bool
    {
        $now ??= time();
        $key = 'qaify-sentinel:admin-ips:' . hash('sha256', $userKey);
        $known = Cache::get($key, []);
        $known = is_array($known) ? array_filter($known, fn ($t) => is_int($t) && $t > $now - self::DAYS * 86400) : [];
        $isNew = $known !== [] && ! isset($known[$ipHash]);

        $known[$ipHash] = $now;
        arsort($known);
        Cache::put($key, array_slice($known, 0, self::MAX, true), now()->addDays(self::DAYS));

        return $isNew;
    }
}
