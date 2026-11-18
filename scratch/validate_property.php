<?php
// Dummy validation test for creating a property
require_once __DIR__ . '/../config/permissions.php';

// Mock user (admin role) – permission is already granted by earlier fix
$user = (object)[
    'user_id' => 1,
    'role' => 'admin',
    'account_type' => 'staff'
];
$actor = (array)$user;

// Simulate POST data
$data = (object)[
    'name' => 'Dummy Property',
    'address' => '123 Test Lane',
    'property_type' => 'house' // lower‑case to test case‑insensitive handling
];

$name = is_object($data) && isset($data->name) && is_string($data->name)
    ? security_clean_text($data->name, 100)
    : '';
$address = is_object($data) && isset($data->address) && is_string($data->address)
    ? security_clean_text($data->address, 255)
    : '';
$propertyType = is_object($data) && isset($data->property_type) && is_string($data->property_type)
    ? trim($data->property_type)
    : '';

$allowedTypes = ['Precast Structure', 'Backroom', 'Apartment Block', 'House'];

// ==== Validation (same as properties.php) ====
$validationErrors = [];
if ($name === '') {
    $validationErrors[] = 'Name is required.';
}
if ($address === '') {
    $validationErrors[] = 'Address is required.';
}
$typeMatch = false;
foreach ($allowedTypes as $type) {
    if (strcasecmp($propertyType, $type) === 0) {
        $propertyType = $type; // normalize
        $typeMatch = true;
        break;
    }
}
if (!$typeMatch) {
    $validationErrors[] = 'A valid property type is required (allowed: ' . implode(', ', $allowedTypes) . ').';
}
if ($validationErrors) {
    echo "Validation failed: " . implode(' ', $validationErrors) . "\n";
    exit(1);
}

echo "Validation succeeded. Normalized type: $propertyType\n";
?>