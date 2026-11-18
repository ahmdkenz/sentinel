<?php

namespace Qaify\Sentinel;

final class Detection
{
    public function __construct(
        public readonly string $kind,
        public readonly string $rule,
        public readonly string $severity,
        public readonly ?string $agent = null,
    ) {}
}
