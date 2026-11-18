<?php

namespace Qaify\Sentinel;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

/** Kirim batch ke Qaify: POST {url}/api/sentinel/batch (kontrak contracts/sentinel-batch.schema.json). */
final class Client
{
    public function send(array $batch): Response
    {
        return Http::withToken((string) config('sentinel.token'))
            ->acceptJson()
            ->timeout((int) config('sentinel.timeout', 5))
            ->withUserAgent('qaify-sentinel/' . Sentinel::VERSION)
            ->post(rtrim((string) config('sentinel.url'), '/') . '/api/sentinel/batch', [
                ...$batch,
                'sensor' => ['version' => Sentinel::VERSION, 'php' => PHP_VERSION, 'laravel' => app()->version()],
            ]);
    }
}
