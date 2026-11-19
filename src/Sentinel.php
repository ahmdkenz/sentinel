<?php

namespace Qaify\Sentinel;

final class Sentinel
{
    public const VERSION = '0.1.1';

    public static function configured(): bool
    {
        return (bool) config('sentinel.enabled') && config('sentinel.url') && config('sentinel.token');
    }
}
