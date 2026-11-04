<?php
// middleware/AuthMiddleware.php - Modern authentication middleware

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../config/jwt.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

class AuthMiddleware {
    
    /**
     * Authenticate user via JWT token
     * @return object Decoded token payload
     */
    public static function authenticate() {
        global $conn;
        
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        
        if (empty($authHeader)) {
            self::unauthorized('No token provided. Access denied.');
        }
        
        // Extract token from Bearer format
        if (stripos($authHeader, 'Bearer ') === 0) {
            $jwt = substr($authHeader, 7);
        } else {
            $jwt = trim($authHeader);
        }
        
        if (empty($jwt)) {
            self::unauthorized('Invalid token format.');
        }
        
        try {
            $decoded = JWT::decode($jwt, new Key(JWT_SECRET, JWT_ALGO));
            
            // Subscription check for non-superadmin, non-tenant, non-maintenance users
            if (!in_array($decoded->role, ['superadmin', 'tenant', 'maintenance'])) {
                $stmt = $conn->prepare("SELECT subscription_status FROM users WHERE id = :id LIMIT 1");
                $stmt->execute([':id' => $decoded->user_id]);
                $status = $stmt->fetchColumn();
                
                if ($status === 'expired') {
                    http_response_code(402);
                    echo json_encode([
                        "error" => "subscription_expired",
                        "message" => "Your subscription has expired. Please renew your plan to continue managing your properties."
                    ]);
                    exit();
                }
            }
            
            return $decoded;
            
        } catch (ExpiredException $e) {
            self::unauthorized('Token has expired.');
        } catch (SignatureInvalidException $e) {
            self::unauthorized('Invalid token signature.');
        } catch (Exception $e) {
            self::unauthorized('Invalid or expired token.');
        }
    }
    
    /**
     * Require specific role(s)
     * @param array|string $roles
     * @return object Decoded token payload
     */
    public static function requireRole($roles) {
        $user = self::authenticate();
        $roles = is_array($roles) ? $roles : [$roles];
        
        if (!in_array($user->role, $roles)) {
            http_response_code(403);
            echo json_encode(["message" => "Unauthorized. Insufficient permissions."]);
            exit();
        }
        
        return $user;
    }
    
    /**
     * Send unauthorized response
     * @param string $message
     */
    private static function unauthorized($message) {
        http_response_code(401);
        echo json_encode(["message" => $message]);
        exit();
    }
}

// Keep backward compatibility
function authenticate() {
    return AuthMiddleware::authenticate();
}
