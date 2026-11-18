<?php

namespace Qaify\Sentinel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Qaify\Sentinel\AdminTracker;
use Qaify\Sentinel\Buffer;
use Qaify\Sentinel\Classifier;
use Qaify\Sentinel\Privacy;
use Qaify\Sentinel\Sentinel;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Middleware global. handle() tidak melakukan apa pun; pencatatan di terminate() — setelah respons terkirim,
 * jadi pengguna tidak menunggu sensor. Seluruhnya dibungkus try/catch: sensor tidak pernah menggagalkan request.
 */
final class Observe
{
    public function __construct(
        private readonly Classifier $classifier,
        private readonly Buffer $buffer,
        private readonly AdminTracker $admins,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        try {
            $this->record($request, $response);
        } catch (Throwable) {
            // diam: sensor keamanan bukan alasan aplikasi error
        }
    }

    private function record(Request $request, Response $response): void
    {
        if (! Sentinel::configured() || $request->is(...(array) config('sentinel.ignore_paths', []))) {
            return;
        }

        $status = $response->getStatusCode();
        $method = strtoupper($request->getMethod());
        $isLogin = $request->is(...(array) config('sentinel.login_paths', []));
        $detection = $method === 'OPTIONS' ? null : $this->classifier->classify(
            $method,
            '/' . ltrim($request->path(), '/'),
            (string) $request->server('QUERY_STRING', ''),
            $status,
            $request->userAgent(),
            $isLogin,
            (bool) config('sentinel.status_events', true),
        );

        // HMAC dengan APP_KEY (stabil walau token sensor dirotasi, tidak pernah keluar dari server aplikasi)
        $privacy = new Privacy('qaify-sentinel:' . (string) config('app.key'));
        $ip = $request->ip();
        $ipHash = $privacy->hash($ip);
        $subject = null;

        if ($detection === null && in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true) && $status < 400) {
            $detection = $this->adminAction($request, $ipHash, $privacy, $subject);
        } elseif ($detection?->kind === 'auth_failed') {
            foreach ((array) config('sentinel.login_fields', ['username', 'email']) as $field) {
                $value = $request->input($field);
                if (is_string($value) && $value !== '') {
                    $subject = $privacy->hash($value);
                    break;
                }
            }
        }

        $this->buffer->append($status, $detection ? array_filter([
            'kind'         => $detection->kind,
            'rule'         => $detection->rule,
            'severity'     => $detection->severity,
            'method'       => $method,
            'path'         => mb_substr('/' . ltrim($request->path(), '/'), 0, 255),
            'status'       => $status,
            'ip_hash'      => $ipHash,
            'ip_prefix'    => Privacy::prefix($ip),
            'subject_hash' => $subject,
            'agent'        => $detection->agent,
        ], fn ($v) => $v !== null) : null);
    }

    private function adminAction(Request $request, ?string $ipHash, Privacy $privacy, ?string &$subject): ?\Qaify\Sentinel\Detection
    {
        $user = $request->user();
        if (! $user || ! $ipHash || ! $this->admins->isAdmin($user)) {
            return null;
        }
        $key = (string) $user->getAuthIdentifier();
        if (! $this->admins->seen($key, $ipHash)) {
            return null;
        }
        $subject = $privacy->hash('user:' . $key);

        return new \Qaify\Sentinel\Detection('admin_new_ip', 'admin.new_ip', 'medium', null);
    }
}
