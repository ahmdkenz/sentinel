<?php

namespace Qaify\Sentinel;

use Throwable;

/**
 * Buffer berkas per menit ({YmdHi}.jsonl, UTC) — tanpa Redis / queue, aman untuk shared hosting.
 * Satu baris per request: {"s":status} untuk penghitung trafik, plus "e" untuk kejadian mencurigakan.
 * Berkas menit yang sudah lewat dikirim sentinel:flush lalu dihapus.
 */
final class Buffer
{
    public function __construct(private readonly string $dir, private readonly int $maxFileBytes = 1048576) {}

    public function append(int $status, ?array $event = null, ?int $time = null): void
    {
        try {
            if (! is_dir($this->dir) && ! @mkdir($this->dir, 0775, true) && ! is_dir($this->dir)) {
                return;
            }
            $file = $this->fileFor($time ?? time());
            // batas ukuran per menit: kejadian dibuang lebih dulu, penghitung tetap jalan sampai 2× batas
            $size = is_file($file) ? (int) @filesize($file) : 0;
            if ($size > 2 * $this->maxFileBytes || ($event !== null && $size > $this->maxFileBytes)) {
                $event = null;
                if ($size > 2 * $this->maxFileBytes) {
                    return;
                }
            }
            $line = json_encode($event === null ? ['s' => $status] : ['s' => $status, 'e' => $event], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
        } catch (Throwable) {
            // sensor tidak boleh mengganggu aplikasi
        }
    }

    public function fileFor(int $time): string
    {
        return $this->dir . DIRECTORY_SEPARATOR . gmdate('YmdHi', $time) . '.jsonl';
    }

    /**
     * Berkas menit yang sudah tertutup (lebih lama dari menit berjalan), terlama dulu.
     *
     * @return list<string>
     */
    public function closedFiles(?int $now = null): array
    {
        $current = basename($this->fileFor($now ?? time()));
        $files = glob($this->dir . DIRECTORY_SEPARATOR . '*.jsonl') ?: [];
        sort($files);

        return array_values(array_filter($files, fn (string $f) => basename($f) < $current));
    }

    /** Hapus berkas lebih tua dari $hours (Qaify tidak terjangkau lama). @return int berkas dihapus */
    public function purgeOlderThan(int $hours, ?int $now = null): int
    {
        $limit = gmdate('YmdHi', ($now ?? time()) - $hours * 3600);
        $deleted = 0;
        foreach (glob($this->dir . DIRECTORY_SEPARATOR . '*.jsonl') ?: [] as $file) {
            if (basename($file, '.jsonl') < $limit && @unlink($file)) {
                $deleted++;
            }
        }

        return $deleted;
    }

    /** "202611190830.jsonl" → "2026-11-19T08:30:00Z" */
    public static function minuteOf(string $file): ?string
    {
        $stamp = basename($file, '.jsonl');
        if (! preg_match('/^\d{12}$/', $stamp)) {
            return null;
        }

        return substr($stamp, 0, 4) . '-' . substr($stamp, 4, 2) . '-' . substr($stamp, 6, 2) . 'T' . substr($stamp, 8, 2) . ':' . substr($stamp, 10, 2) . ':00Z';
    }
}
