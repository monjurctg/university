<?php
// api/users.php
require_once 'config.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // List all members (students)
    // We are treating 'students' table as members for now based on schema analysis
    $stmt = $pdo->query("SELECT id, student_id, name, email, created_at FROM students ORDER BY id DESC");
    $members = $stmt->fetchAll();
    echo json_encode($members);

} elseif ($method === 'POST') {
    // Add new member (Admin adds student)
    $data = json_decode(file_get_contents("php://input"), true);

    $name = $data['name'];
    $student_id = $data['student_id'];
    $email = $data['email'];
    $email = $data['email'];
    // Use provided password or default to '123456'
    $raw_password = !empty($data['password']) ? $data['password'] : '123456';
    $password = password_hash($raw_password, PASSWORD_DEFAULT);

    // Check if student_id exists
    $stmt = $pdo->prepare("SELECT id FROM students WHERE student_id = ?");
    $stmt->execute([$student_id]);
    if ($stmt->fetch()) {
        echo json_encode(['success' => false, 'message' => 'Student ID already exists']);
        exit;
    }

    $stmt = $pdo->prepare("INSERT INTO students (student_id, name, email, password) VALUES (?, ?, ?, ?)");
    if ($stmt->execute([$student_id, $name, $email, $password])) {
        echo json_encode(['success' => true, 'message' => 'Member added successfully']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to add member']);
    }
}
?>
