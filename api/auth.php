<?php
require_once 'config.php';

$data = json_decode(file_get_contents("php://input"));

if (!isset($data->action)) {
    echo json_encode(["status" => "error", "message" => "No action specified"]);
    exit;
}

if ($data->action === 'login_admin') {
    $email = $data->email;
    $password = $data->password;

    $stmt = $pdo->prepare("SELECT * FROM admins WHERE email = ?");
    $stmt->execute([$email]);
    $admin = $stmt->fetch();

    if ($admin && password_verify($password, $admin['password'])) {
        // In a real app, generate a token. Here we just return success and user info.
        unset($admin['password']);
        echo json_encode(["status" => "success", "user" => $admin, "role" => "admin"]);
    } else {
        echo json_encode(["status" => "error", "message" => "Invalid credentials"]);
    }

} elseif ($data->action === 'login_student') {
    $student_id = $data->student_id;
    $password = $data->password;

    $stmt = $pdo->prepare("SELECT * FROM students WHERE student_id = ?");
    $stmt->execute([$student_id]);
    $student = $stmt->fetch();

    if ($student && password_verify($password, $student['password'])) {
        unset($student['password']);
        echo json_encode(["status" => "success", "user" => $student, "role" => "student"]);
    } else {
        echo json_encode(["status" => "error", "message" => "Invalid credentials"]);
    }
} else {
    echo json_encode(["status" => "error", "message" => "Invalid action"]);
}
?>
