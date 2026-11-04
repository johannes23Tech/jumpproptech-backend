<?php
// config/jwt.php - JWT configuration

require_once __DIR__ . '/config.php';

define('JWT_SECRET', getenv('JWT_SECRET') ?: 'jumpproptech_super_secret_key_2025');
define('JWT_ALGO', 'HS256');
define('JWT_EXPIRY', intval(getenv('JWT_EXPIRY')) ?: 86400); // 24 hours
define('JWT_ISSUER', getenv('JWT_ISSUER') ?: 'jumpproptech');
