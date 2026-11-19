# qaify/sentinel

A security activity sensor for Laravel apps. It sends activity to the **SOC Qaify** (the attack globe, Sentinel incidents, and Telegram/email notifications).

It records, without slowing requests down (all work happens in `terminate()` after the response is sent):

| Type | Example | Default severity |
| --- | --- | --- |
| `auth_failed` | 401/403/429 on the login endpoint | low / medium (locked) |
| `payload` | SQLi, XSS, traversal, LFI, RCE, SSTI, log4shell in the path/query | medium; **high** if answered with 2xx |
| `probe_path` | `/.env`, `/.git`, `wp-admin`, `phpmyadmin`, backup files | low; **high** if the file is actually served |
| `scanner` | user-agent sqlmap, nikto, nuclei, … | medium |
| `admin_new_ip` | an admin performs a POST/PUT/PATCH/DELETE from an IP not seen in 30 days | medium |
| `server_error`, `unauthorized`, `forbidden`, `rate_limited` | 5xx / 401 / 403 / 429 outside login | low |

Qaify then decides on incidents: brute force, credential stuffing, a payload that got through, a 5xx spike, a 401/403/429 spike, and so on.

## Privacy

- No request body, query values, headers, cookies, or **raw IPs** ever leave the server.
- The IP is sent as `ip_hash` (an HMAC with `APP_KEY`) plus `ip_prefix` (the /24 or /48 network address), which Qaify only uses for geolocation and then **discards**.
- The login username is sent only as `subject_hash` (an HMAC). Payload detection sends only the rule id (e.g. `sqli.union`), never the text that matched.

## Installation

1. Create a token in Qaify: **SOC → app → Domain & Sensor tab → Create Sentinel token**.
2. Install the package and fill in `.env`:

   ```bash
   composer require qaify/sentinel
   ```

   ```dotenv
   QAIFY_SENTINEL_URL=https://api.qaify.example
   QAIFY_SENTINEL_TOKEN=qsn_…
   ```

3. Run `php artisan config:cache` (if config is cached), then `php artisan sentinel:test` to check the connection.
4. The scheduler must be running (`* * * * * php artisan schedule:run`). `sentinel:flush` is scheduled automatically every minute.

The middleware is registered globally on its own. Nothing needs to be added to `bootstrap/app.php`.

## Configuration (optional)

To publish the config: `php artisan vendor:publish --tag=sentinel-config`.

- `login_paths`: login endpoint patterns (default `api/*/auth/login`, `api/auth/login`, `login`).
- `login_fields`: the username field that gets hashed (`username`, `email`).
- `admin_check`: a callable or `"Class@method"`. Default: `$user->hasRole(['ADMIN'])` (spatie/laravel-permission).
- `ignore_paths`: paths that are never recorded (`up`, `health`, …).
- `status_events`: `false` sends only traffic counters for 401/403/429/5xx outside login.
- `buffer_path`: the per-minute buffer folder (default `storage/framework/sentinel`, capped at 1 MB per minute, purged after 24 hours).

## How it works

1. Each request appends one line to `storage/framework/sentinel/{YmdHi}.jsonl` (`flock`, ±100 bytes).
2. `sentinel:flush` sends each closed minute as one batch to `POST {url}/api/sentinel/batch`. Identical events are merged (`count`).
3. The `batch_id` is deterministic, so resends are safe: Qaify ignores duplicates.
4. On 2xx the file is deleted. On a network error or 5xx it is retried the next minute. On 401 it stops; check the token.
5. When the app is quiet (no requests, so no minute files) and nothing was sent for 5 minutes, `sentinel:flush` sends an empty heartbeat batch. Without it, Qaify would report "Sensor Sentinel stopped sending data" every night. The last successful send is stored as the mtime of `{buffer_path}/.heartbeat`.

Qaify's own scans (user-agent `QaifyScanner` / `QaifyMonitor`) are tagged `agent=qaify`. They are not counted as attacks.

Contract: `contracts/sentinel-batch.schema.json` in the Qaify repo.

## Development

```bash
composer install
composer test
```

## Release

This folder is its own git repository (`main`), published to the public `qaify-sentinel` GitHub repo. To release: commit, add a tag `v0.x.y`, and run `git push origin main --tags`. Packagist picks up the tag through its GitHub webhook.

If an app commits its `vendor/` directory (for example a shared-hosting deploy), run `composer require` locally and commit `vendor/`. Don't run it on the server.
