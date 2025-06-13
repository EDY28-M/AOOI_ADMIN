<?php

return [
    'paths' => ['api/*', 'sanctum/csrf-cookie'],

    'allowed_methods' => ['*'],

    'allowed_origins' => [
        'http://localhost:4200',
        'http://localhost:5000',
        'http://127.0.0.1:4200',
        'http://127.0.0.1:5000',
        // Añadidos para tu frontend en el puerto 8081:
        'http://localhost:8081',
        'http://127.0.0.1:8081',
    ],

    'allowed_origins_patterns' => [],
        // ⚠️ Prueba temporal: permite cualquier origen
    'allowed_origins' => ['*'],

    'allowed_headers' => ['*'],

    'exposed_headers' => [],

    'max_age' => 0,

    'supports_credentials' => false,
];
