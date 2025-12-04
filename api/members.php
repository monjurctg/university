<?php
// api/members.php
require_once 'config.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // Fetch all members
    $stmt = $pdo->query("SELECT * FROM members ORDER BY id DESC");
    $members = $stmt->fetchAll();
    echo json_encode($members);

} elseif ($method === 'POST') {
    // Add new member
    $data = json_decode(file_get_contents("php://input"), true);

    $name = $data['name'];
    $member_id = $data['member_id'];
    $email = $data['email'];
    $date = date('Y-m-d'); // Current date

    // Check if Member ID exists
    $stmt = $pdo->prepare("SELECT id FROM members WHERE member_id = ?");
    $stmt->execute([$member_id]);
    if ($stmt->fetch()) {
        echo json_encode(['success' => false, 'message' => 'Member ID already exists']);
        exit;
    }

    $stmt = $pdo->prepare("INSERT INTO members (member_id, name, email, registered_date) VALUES (?, ?, ?, ?)");
    if ($stmt->execute([$member_id, $name, $email, $date])) {
        echo json_encode(['success' => true, 'message' => 'Member registered successfully']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to register member']);
    }
}
?>
