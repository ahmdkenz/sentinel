<?php

namespace Qaify\Sentinel\Console;

use Illuminate\Console\Command;
use Qaify\Sentinel\Buffer;
use Qaify\Sentinel\Client;
use Qaify\Sentinel\Sentinel;
use Throwable;

/**
 * sentinel:flush — tiap menit lewat scheduler. Satu berkas menit = satu batch (dipecah bila > 500 kejadian):
 * penghitung trafik + kejadian identik digabung (count). batch_id deterministik → kirim ulang aman (idempoten di Qaify).
 * 2xx / 422 → berkas dihapus; 401 → berhenti (token salah / dirotasi); galat lain → dicoba lagi menit berikutnya.
 * Tidak ada yang dikirim selama 5 menit → heartbeat (batch kosong) agar Qaify tahu sensor masih hidup.
 */
final class FlushCommand extends Command
{
    protected $signature = 'sentinel:flush';

    protected $description = 'Kirim aktivitas keamanan yang tercatat ke Qaify SOC';

    private const MAX_EVENTS = 500;

    /** Batas sepi sebelum heartbeat dikirim; jauh di bawah silent_minutes Qaify (30 menit). */
    private const HEARTBEAT_SECONDS = 300;

    public function handle(Buffer $buffer, Client $client): int
    {
        if (! Sentinel::configured()) {
            $this->line('Sentinel belum dikonfigurasi (QAIFY_SENTINEL_URL / QAIFY_SENTINEL_TOKEN).');

            return self::SUCCESS;
        }

        $buffer->purgeOlderThan((int) config('sentinel.max_age_hours', 24));
        $sent = 0;

        foreach (array_slice($buffer->closedFiles(), 0, (int) config('sentinel.max_files_per_flush', 20)) as $file) {
            $minute = Buffer::minuteOf($file);
            if ($minute === null) {
                @unlink($file);

                continue;
            }
            [$traffic, $events] = self::aggregate($file, $minute);
            $chunks = $events === [] ? [[]] : array_chunk($events, self::MAX_EVENTS);

            foreach ($chunks as $i => $chunk) {
                try {
                    $response = $client->send([
                        'batch_id' => substr(hash('sha256', (string) config('sentinel.token') . '|' . basename($file) . "|{$i}"), 0, 40),
                        'traffic'  => $i === 0 ? [$traffic] : [],
                        'events'   => $chunk,
                    ]);
                } catch (Throwable $e) {
                    $this->warn('Qaify tidak terjangkau: ' . $e->getMessage());

                    return self::SUCCESS;
                }
                if ($response->status() === 401 || $response->status() === 429) {
                    $this->warn("Qaify menolak batch (HTTP {$response->status()}).");

                    return self::SUCCESS;
                }
                if ($response->serverError()) {
                    $this->warn("Qaify galat (HTTP {$response->status()}); dicoba lagi nanti.");

                    return self::SUCCESS;
                }
                // 2xx diterima; 4xx lain (mis. 422) tidak akan berhasil walau dikirim ulang
            }
            @unlink($file);
            $sent++;
        }

        if ($sent > 0) {
            $this->markAlive($buffer);
        } elseif ($this->heartbeatDue($buffer)) {
            $this->heartbeat($buffer, $client);
        }

        $this->info("Batch terkirim: {$sent}");

        return self::SUCCESS;
    }

    /**
     * Aplikasi sepi (malam / akhir pekan) = tidak ada berkas menit = tidak ada batch. Tanpa heartbeat, Qaify
     * mengira sensor mati ("Sensor Sentinel berhenti mengirim data"). Batch kosong tiap HEARTBEAT_SECONDS;
     * batch_id deterministik per slot → kirim ulang aman.
     */
    private function heartbeat(Buffer $buffer, Client $client): void
    {
        $slot = intdiv(time(), self::HEARTBEAT_SECONDS);
        try {
            $response = $client->send([
                'batch_id' => 'hb-' . substr(hash('sha256', (string) config('sentinel.token') . "|hb|{$slot}"), 0, 40),
                'traffic'  => [],
                'events'   => [],
            ]);
        } catch (Throwable $e) {
            $this->warn('Qaify tidak terjangkau: ' . $e->getMessage());

            return;
        }
        if ($response->successful()) {
            $this->markAlive($buffer);
            $this->line('Heartbeat terkirim.');
        } else {
            $this->warn("Heartbeat ditolak (HTTP {$response->status()}).");
        }
    }

    private function heartbeatDue(Buffer $buffer): bool
    {
        $mtime = @filemtime($buffer->heartbeatFile());

        return $mtime === false || time() - $mtime >= self::HEARTBEAT_SECONDS;
    }

    private function markAlive(Buffer $buffer): void
    {
        $file = $buffer->heartbeatFile();
        $dir = dirname($file);
        if (is_dir($dir) || @mkdir($dir, 0775, true)) {
            @touch($file);
        }
    }

    /**
     * @return array{0: array<string, int|string>, 1: list<array<string, mixed>>} penghitung trafik + kejadian tergabung
     */
    public static function aggregate(string $file, string $minute): array
    {
        $traffic = ['minute' => $minute, 'total' => 0, 's4xx' => 0, 's401' => 0, 's403' => 0, 's429' => 0, 's5xx' => 0];
        $events = [];
        $handle = @fopen($file, 'r');
        if ($handle === false) {
            return [$traffic, []];
        }

        while (($line = fgets($handle)) !== false) {
            $row = json_decode($line, true);
            if (! is_array($row) || ! isset($row['s'])) {
                continue;
            }
            $s = (int) $row['s'];
            $traffic['total']++;
            if ($s >= 400 && $s < 500) {
                $traffic['s4xx']++;
            }
            if (in_array($s, [401, 403, 429], true)) {
                $traffic["s{$s}"]++;
            }
            if ($s >= 500) {
                $traffic['s5xx']++;
            }

            if (isset($row['e']) && is_array($row['e'])) {
                $e = $row['e'];
                $key = hash('xxh128', json_encode($e));
                if (isset($events[$key])) {
                    $events[$key]['count']++;
                } else {
                    $events[$key] = ['at' => $minute, ...$e, 'count' => 1];
                }
            }
        }
        fclose($handle);

        // batas per batch: kejadian terparah dulu
        $rank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
        $events = array_values($events);
        usort($events, fn ($a, $b) => ($rank[$a['severity']] ?? 9) <=> ($rank[$b['severity']] ?? 9) ?: $b['count'] <=> $a['count']);

        return [$traffic, array_slice($events, 0, 5 * self::MAX_EVENTS)];
    }
}
