<?php
// middleware/AuthMiddleware.php
//
// Deprecated compatibility shim.
//
// The canonical implementation is authenticate() in middleware/check_role.php.
// This class used to duplicate JWT decoding with weaker checks (no token
// version, no denylist, no subscription re-read). Two auth implementations is
// exactly how auth bypasses creep in, so this now simply delegates.

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/check_role.php';

if (!class_exists('AuthMiddleware')) {
    class AuthMiddleware
    {
        /**
         * @return object Decoded token payload (authenticated user).
         */
        public static function authenticate()
        {
            return \authenticate();
        }

        /**
         * Require one of the given roles.
         *
         * @param array|string $roles
         * @return object Decoded token payload.
         */
        public static function requireRole($roles)
        {
            $user = \authenticate();
            $roles = is_array($roles) ? $roles : [$roles];

            if (!in_array($user->role, $roles, true)) {
                security_json_response(403, ["message" => "Unauthorized. Insufficient permissions."]);
            }

            return $user;
        }
    }
}
