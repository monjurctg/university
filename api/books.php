<?php
require_once 'config.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // List books
    $sql = "SELECT * FROM books";
    if (isset($_GET['search'])) {
        $search = "%" . $_GET['search'] . "%";
        $sql .= " WHERE title LIKE ? OR author LIKE ? OR isbn LIKE ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$search, $search, $search]);
    } else {
        $stmt = $pdo->query($sql);
    }

    $books = $stmt->fetchAll();
    echo json_encode($books);

} elseif ($method === 'POST') {
    // Add new book (Admin only - simplified check)
    $data = json_decode(file_get_contents("php://input"));

    if (!isset($data->title) || !isset($data->isbn)) {
        echo json_encode(["status" => "error", "message" => "Missing required fields"]);
        exit;
    }

    try {
        $stmt = $pdo->prepare("INSERT INTO books (title, author, isbn, quantity, available) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([
            $data->title,
            $data->author,
            $data->isbn,
            $data->quantity,
            $data->quantity // Initially available = quantity
        ]);
        echo json_encode(["status" => "success", "message" => "Book added successfully"]);
    } catch (PDOException $e) {
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
} elseif ($method === 'DELETE') {
    // Delete book
    $data = json_decode(file_get_contents("php://input"));

    if (!isset($data->id)) {
        echo json_encode(["status" => "error", "message" => "Book ID required"]);
        exit;
    }

    try {
        $stmt = $pdo->prepare("DELETE FROM books WHERE id = ?");
        $stmt->execute([$data->id]);
        echo json_encode(["status" => "success", "message" => "Book deleted successfully"]);
    } catch (PDOException $e) {
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
}
?>
