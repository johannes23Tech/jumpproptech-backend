<?php
require_once '../config/db.php';
require_once '../middleware/check_role.php';

$user = authenticate();

$query = "SELECT 
    (SELECT COUNT(*) FROM properties WHERE landlord_id = :user_id) as total_properties,
    (SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = :user_id) as total_units,
    (SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = :user_id AND u.status = 'Occupied') as occupied,
    (SELECT COUNT(*) FROM units u JOIN properties p ON u.property_id = p.id WHERE p.landlord_id = :user_id AND u.status = 'Vacant') as vacant,
    (SELECT SUM(amount) FROM rent_records WHERE status = 'Paid') as collected,
    (SELECT SUM(amount) FROM rent_records WHERE status = 'Pending') as pending";

$stmt = $conn->prepare($query);
$stmt->bindParam(':user_id', $user->user_id);
$stmt->execute();
$stats = $stmt->fetch(PDO::FETCH_ASSOC);

echo json_encode($stats);
?>