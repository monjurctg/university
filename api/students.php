<?php
require_once 'config.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // If student_id is provided, get specific student details (e.g. for profile)
    if (isset($_GET['student_id'])) {
        $stmt = $pdo->prepare("SELECT id, student_id, name, email, avatar, created_at FROM students WHERE student_id = ?");
        $stmt->execute([$_GET['student_id']]);
        $student = $stmt->fetch();
        if ($student) {
            echo json_encode($student);
        } else {
            echo json_encode(["status" => "error", "message" => "Student not found"]);
        }
    } else {
        // List all students (for Admin)
        $stmt = $pdo->query("SELECT id, student_id, name, email, avatar, created_at FROM students");
        $students = $stmt->fetchAll();
        echo json_encode($students);
    }

} elseif ($method === 'POST') {
    // Register new student (Admin)
    $data = json_decode(file_get_contents("php://input"));

    if (!isset($data->student_id) || !isset($data->name) || !isset($data->email)) {
        echo json_encode(["status" => "error", "message" => "Missing required fields"]);
        exit;
    }

    // Default password for new students: 'pass123' if not provided
    $raw_password = isset($data->password) && !empty($data->password) ? $data->password : 'pass123';
    $password = password_hash($raw_password, PASSWORD_DEFAULT);

    try {
        $stmt = $pdo->prepare("INSERT INTO students (student_id, name, email, password) VALUES (?, ?, ?, ?)");
        $stmt->execute([
            $data->student_id,
            $data->name,
            $data->email,
            $password
        ]);
        echo json_encode(["status" => "success", "message" => "Student registered successfully"]);
    } catch (PDOException $e) {
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
} elseif ($method === 'PUT') {
    // Update student profile (Self)
    $data = json_decode(file_get_contents("php://input"));

    if (!isset($data->student_id)) {
        echo json_encode(["status" => "error", "message" => "Student ID required"]);
        exit;
    }

    $sql = "UPDATE students SET name = ?, email = ?";
    $params = [$data->name, $data->email];

    if (!empty($data->password)) {
        $sql .= ", password = ?";
        $params[] = password_hash($data->password, PASSWORD_DEFAULT);
    }

    if (!empty($data->avatar)) {
        $sql .= ", avatar = ?";
        $params[] = $data->avatar;
    }

    $sql .= " WHERE student_id = ?";
    $params[] = $data->student_id;

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        echo json_encode(["status" => "success", "message" => "Profile updated successfully"]);
    } catch (PDOException $e) {
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
} elseif ($method === 'DELETE') {
    // Delete student (Admin)
    $data = json_decode(file_get_contents("php://input"));

    if (!isset($data->id) && !isset($data->student_id)) {
        echo json_encode(["status" => "error", "message" => "Student identifier required"]);
        exit;
    }

    try {
        if (isset($data->id)) {
            $stmt = $pdo->prepare("DELETE FROM students WHERE id = ?");
            $stmt->execute([$data->id]);
        } else {
            $stmt = $pdo->prepare("DELETE FROM students WHERE student_id = ?");
            $stmt->execute([$data->student_id]);
        }
        echo json_encode(["status" => "success", "message" => "Student deleted successfully"]);
    } catch (PDOException $e) {
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
}
?>
