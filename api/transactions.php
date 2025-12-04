<?php
require_once 'config.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    // Get transactions. If student_id is provided, filter by student.
    $sql = "SELECT t.*, b.title as book_title, b.author as book_author
            FROM transactions t
            JOIN books b ON t.book_id = b.id";

    if (isset($_GET['student_id'])) {
        $sql .= " WHERE t.student_id = ? ORDER BY t.issue_date DESC";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$_GET['student_id']]);
    } else {
        $sql .= " ORDER BY t.issue_date DESC LIMIT 50"; // Admin view: latest 50
        $stmt = $pdo->query($sql);
    }

    $transactions = $stmt->fetchAll();
    echo json_encode($transactions);

} elseif ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"));
    $action = $data->action ?? '';

    if ($action === 'issue') {
        // Request Book Issue (Student)
        $student_id = $data->student_id;
        $isbn = $data->isbn;

        try {
            // 1. Find Book
            $stmt = $pdo->prepare("SELECT id, available FROM books WHERE isbn = ?");
            $stmt->execute([$isbn]);
            $book = $stmt->fetch();

            if (!$book || $book['available'] < 1) {
                throw new Exception("Book not available or not found.");
            }

            // 2. Create Transaction (Status: requested)
            $issue_date = date('Y-m-d');
            $due_date = date('Y-m-d', strtotime('+14 days')); // Tentative due date

            $stmt = $pdo->prepare("INSERT INTO transactions (student_id, book_id, issue_date, due_date, status) VALUES (?, ?, ?, ?, 'requested')");
            $stmt->execute([$student_id, $book['id'], $issue_date, $due_date]);

            // NOTE: We do NOT decrease availability yet. That happens on approval.

            echo json_encode(["status" => "success", "message" => "Book requested successfully. Waiting for admin approval."]);

        } catch (Exception $e) {
            echo json_encode(["status" => "error", "message" => $e->getMessage()]);
        }

    } elseif ($action === 'approve') {
        // Approve Request (Admin)
        $transaction_id = $data->transaction_id;

        try {
            $pdo->beginTransaction();

            // 1. Get Transaction
            $stmt = $pdo->prepare("SELECT book_id, status FROM transactions WHERE id = ?");
            $stmt->execute([$transaction_id]);
            $trans = $stmt->fetch();

            if (!$trans || $trans['status'] !== 'requested') {
                throw new Exception("Invalid transaction or not in requested state.");
            }

            // 2. Check Availability Again
            $stmt = $pdo->prepare("SELECT available FROM books WHERE id = ?");
            $stmt->execute([$trans['book_id']]);
            $book = $stmt->fetch();

            if ($book['available'] < 1) {
                throw new Exception("Book is no longer available.");
            }

            // 3. Update Transaction Status
            $stmt = $pdo->prepare("UPDATE transactions SET status = 'issued' WHERE id = ?");
            $stmt->execute([$transaction_id]);

            // 4. Decrease Availability
            $stmt = $pdo->prepare("UPDATE books SET available = available - 1 WHERE id = ?");
            $stmt->execute([$trans['book_id']]);

            $pdo->commit();
            echo json_encode(["status" => "success", "message" => "Request approved. Book issued."]);

        } catch (Exception $e) {
            $pdo->rollBack();
            echo json_encode(["status" => "error", "message" => $e->getMessage()]);
        }

    } elseif ($action === 'reject') {
        // Reject Request (Admin)
        $transaction_id = $data->transaction_id;

        try {
            $stmt = $pdo->prepare("UPDATE transactions SET status = 'rejected' WHERE id = ?");
            $stmt->execute([$transaction_id]);
            echo json_encode(["status" => "success", "message" => "Request rejected."]);
        } catch (Exception $e) {
            echo json_encode(["status" => "error", "message" => $e->getMessage()]);
        }

    } elseif ($action === 'return') {
        // Return Book
        $transaction_id = $data->transaction_id;

        try {
            $pdo->beginTransaction();

            // 1. Get Transaction
            $stmt = $pdo->prepare("SELECT book_id, status FROM transactions WHERE id = ?");
            $stmt->execute([$transaction_id]);
            $trans = $stmt->fetch();

            if (!$trans || $trans['status'] !== 'issued') {
                throw new Exception("Invalid transaction or not currently issued.");
            }

            // 2. Update Transaction
            $return_date = date('Y-m-d');
            $stmt = $pdo->prepare("UPDATE transactions SET return_date = ?, status = 'returned' WHERE id = ?");
            $stmt->execute([$return_date, $transaction_id]);

            // 3. Increase Availability
            $stmt = $pdo->prepare("UPDATE books SET available = available + 1 WHERE id = ?");
            $stmt->execute([$trans['book_id']]);

            $pdo->commit();
            echo json_encode(["status" => "success", "message" => "Book returned successfully"]);

        } catch (Exception $e) {
            $pdo->rollBack();
            echo json_encode(["status" => "error", "message" => $e->getMessage()]);
        }
    } else {
        echo json_encode(["status" => "error", "message" => "Invalid action"]);
    }
}
?>
