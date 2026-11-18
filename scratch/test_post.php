<?php
// Simple test client for the properties POST endpoint
$url = 'http://127.0.0.1:8080/properties.php';
$data = [
    'name' => 'Live Test Property',
    'address' => '1 Test St',
    'property_type' => 'house', // lower‑case to test case‑insensitivity
];
$payload = json_encode($data);

$options = [
    'http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/json\r\n",
        'content' => $payload,
        'ignore_errors' => true,
    ],
];
$context = stream_context_create($options);
$response = file_get_contents($url, false, $context);

echo "Response code: " . $http_response_header[0] . "\n";
echo $response . "\n";
?>