<?php

return [
    // Sensor aktif hanya bila URL + token terisi (token dibuat di Qaify → SOC → aplikasi → Domain & Sensor)
    'enabled' => env('QAIFY_SENTINEL_ENABLED', true),
    'url'     => env('QAIFY_SENTINEL_URL'),
    'token'   => env('QAIFY_SENTINEL_TOKEN'),

    // Middleware global didaftarkan otomatis; false = daftarkan sendiri Qaify\Sentinel\Http\Middleware\Observe
    'register_middleware' => true,

    // Endpoint login (pola Request::is): 401/403/429 di sini = login gagal
    'login_paths' => ['api/*/auth/login', 'api/auth/login', 'login'],
    // Field username yang di-HMAC (subject_hash) untuk mendeteksi credential stuffing; nilainya tidak dikirim
    'login_fields' => ['username', 'email'],

    // Admin beraksi dari IP baru: null = $user->hasRole('ADMIN') bila tersedia. Bisa diganti callable / "Class@method".
    'admin_check' => null,
    'admin_roles' => ['ADMIN'],

    // Tidak dicatat sama sekali (healthcheck, broadcasting)
    'ignore_paths' => ['up', 'health', 'healthz', 'broadcasting/auth'],

    // Kejadian berbasis status (401/403/429/5xx di luar login) ikut dikirim sebagai kejadian; penghitung trafik selalu dikirim
    'status_events' => true,

    // Buffer berkas per menit (tanpa Redis / queue); flush tiap menit lewat scheduler
    'buffer_path'      => storage_path('framework/sentinel'),
    'max_file_bytes'   => 1024 * 1024,
    'max_files_per_flush' => 20,
    'max_age_hours'    => 24,
    'timeout'          => 5,
    'schedule'         => true,
];
