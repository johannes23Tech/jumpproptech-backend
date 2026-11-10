<?php
// config/config.php

// 1. Load environment variables if .env exists
if (file_exists(__DIR__ . '/../.env')) {
    $lines = file(__DIR__ . '/../.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            if (!array_key_exists($key, $_ENV) && !getenv($key)) {
                putenv("$key=$value");
                $_ENV[$key] = $value;
            }
        }
    }
}

// 2. Security headers (defence in depth; mirror these at the web server).
if (!headers_sent()) {
    header_remove('X-Powered-By');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header('Cross-Origin-Resource-Policy: same-site');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('X-Permitted-Cross-Domain-Policies: none');
    header('X-Robots-Tag: noindex, nofollow');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'");

    // Every API response can contain personal or financial data. Never let a
    // browser, proxy or CDN cache it.
    header('Cache-Control: no-store, no-cache, must-revalidate, private');
    header('Pragma: no-cache');
    header('Expires: 0');

    $isHttps = (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? null) === '443')
        || (strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    if ($isHttps) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

// 3. CORS Headers (allowlist; set CORS_ALLOWED_ORIGINS as a comma-separated
// list in production). Never reflect an arbitrary origin.
//
// APP_ENV defaults to "production" so a missing .env fails safe (no error
// disclosure, no localhost origins). Set APP_ENV=development locally.
$appEnv = getenv('APP_ENV');
if ($appEnv === false || trim($appEnv) === '') {
    $appEnv = 'production';
}
$isProduction = $appEnv === 'production';

$defaultOrigins = ['https://jumpproptech-frontend.vercel.app'];
if (!$isProduction) {
    // Dev-only origins must never be allowlisted in production.
    $defaultOrigins = array_merge($defaultOrigins, [
        'http://localhost:3000',
        'http://localhost:5173',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5173',
    ]);
}

$configuredOrigins = getenv('CORS_ALLOWED_ORIGINS');
if ($configuredOrigins === false || trim($configuredOrigins) === '') {
    $configuredOrigins = getenv('ALLOWED_ORIGINS');
}
$allowedOrigins = $defaultOrigins;
if ($configuredOrigins !== false && trim($configuredOrigins) !== '') {
    $allowedOrigins = array_values(array_filter(array_map('trim', explode(',', $configuredOrigins))));
}

$requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';
$originAllowed = $requestOrigin === '' || in_array($requestOrigin, $allowedOrigins, true);

// Reject browser requests from unknown origins outright. Requests without an
// Origin header (cron jobs, server-to-server, CLI) are unaffected. This is
// defence in depth: authentication uses Bearer tokens, not cookies, so CSRF
// is already largely inapplicable.
if (!$originAllowed) {
    http_response_code(403);
    header("Vary: Origin");
    echo json_encode(["message" => "Origin not allowed."]);
    exit();
}

header("Vary: Origin");
if ($requestOrigin !== '') {
    header("Access-Control-Allow-Origin: " . $requestOrigin);
}

header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE, PUT, PATCH");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Access-Control-Max-Age: 600");
header("Content-Type: application/json; charset=UTF-8");

// 4. Handle preflight requests
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// 5. Error reporting. Default to silent: a missing APP_ENV must never leak
// stack traces or configuration to clients.
if ($isProduction) {
    error_reporting(0);
    ini_set('display_errors', 0);
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}

// 6. Timezone
date_default_timezone_set(getenv('APP_TIMEZONE') ?: 'Africa/Johannesburg');
?>