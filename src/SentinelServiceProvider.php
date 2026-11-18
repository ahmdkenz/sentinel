<?php

namespace Qaify\Sentinel;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;
use Qaify\Sentinel\Console\FlushCommand;
use Qaify\Sentinel\Console\TestCommand;
use Qaify\Sentinel\Http\Middleware\Observe;
use Throwable;

final class SentinelServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sentinel.php', 'sentinel');

        $this->app->singleton(Buffer::class, fn () => new Buffer(
            (string) config('sentinel.buffer_path', storage_path('framework/sentinel')),
            (int) config('sentinel.max_file_bytes', 1048576),
        ));
        $this->app->singleton(Classifier::class);
        $this->app->singleton(AdminTracker::class);
        // satu instance: terminate() memakai objek yang sama dengan handle()
        $this->app->singleton(Observe::class);
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../config/sentinel.php' => config_path('sentinel.php')], 'sentinel-config');

        if ($this->app->runningInConsole()) {
            $this->commands([FlushCommand::class, TestCommand::class]);
        }

        if (config('sentinel.register_middleware', true)) {
            try {
                $kernel = $this->app->make(Kernel::class);
                if (method_exists($kernel, 'pushMiddleware')) {
                    $kernel->pushMiddleware(Observe::class);
                }
            } catch (Throwable) {
                // kernel HTTP tidak tersedia (mis. konteks CLI tertentu)
            }
        }

        if (config('sentinel.schedule', true)) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
                $schedule->command('sentinel:flush')->everyMinute()->withoutOverlapping(5)->name('qaify-sentinel-flush');
            });
        }
    }
}
