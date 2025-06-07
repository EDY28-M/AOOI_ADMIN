<?php

namespace App\Http\Middleware;            // (o App\Http\Kernel, según hayas puesto tu namespace)
 
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Fruitcake\Cors\HandleCors;          // importa también la clase de CORS

class Kernel extends HttpKernel
{
    /**
     * The application's global HTTP middleware stack.
     *
     * @var array<int, class-string|string>
     */
    protected $middleware = [
        // ¡Aquí dentro!
        \Fruitcake\Cors\HandleCors::class,
        // … otros middleware globales que ya tenías …
    ];

    /**
     * The application's route middleware groups.
     *
     * @var array<string, array<int, class-string|string>>
     */
    protected $middlewareGroups = [
        'web' => [
            // …
        ],

        'api' => [
            // Si prefieres, también puedes añadir aquí:
            // \Fruitcake\Cors\HandleCors::class,
            'throttle:api',
            \Illuminate\Routing\Middleware\SubstituteBindings::class,
        ],
    ];

    /**
     * The application's route middleware.
     *
     * These middleware may be assigned to groups or used individually.
     *
     * @var array<string, class-string|string>
     */
    protected $routeMiddleware = [
        // …
    ];
}
