<?php
// api/borrow.php
require_once 'config.php';

$action = $_GET['action'] ?? '';
$data = json_decode(file_get_contents("php://input"), true);

if ($action === 'issue') {
    $student_id = $data['student_id'];
    $isbn = $data['isbn']; // Using ISBN to find book, or book_id directly if available

    // Find book by ISBN
    $stmt = $pdo->prepare("SELECT id, available FROM books WHERE isbn = ?");
    $stmt->execute([$isbn]);
    $book = $stmt->fetch();

    if (!$book) {
        echo json_encode(['success' => false, 'message' => 'Book not found']);
        exit;
    }

    if ($book['available'] < 1) {
        echo json_encode(['success' => false, 'message' => 'Book is out of stock']);
        exit;
    }

    // Check if student already has this book issued or requested
    $stmt = $pdo->prepare("SELECT id FROM transactions WHERE student_id = ? AND book_id = ? AND status IN ('issued', 'requested')");
    $stmt->execute([$student_id, $book['id']]);
    if ($stmt->fetch()) {
        echo json_encode(['success' => false, 'message' => 'You already have this book issued or requested']);
        exit;
    }

    // Request Book (Issue with status 'requested')
    // Note: We do NOT decrease availability yet. That happens on approval.
    $pdo->beginTransaction();
    try {
        $issue_date = date('Y-m-d');
        $due_date = date('Y-m-d', strtotime('+14 days')); // 2 weeks due from request? Or from approval? Usually approval.
        // For simplicity, let's set dates now, but maybe update issue_date on approval.

        $stmt = $pdo->prepare("INSERT INTO transactions (student_id, book_id, issue_date, due_date, status) VALUES (?, ?, ?, ?, 'requested')");
        $stmt->execute([$student_id, $book['id'], $issue_date, $due_date]);

        $pdo->commit();
        echo json_encode(['success' => true, 'message' => 'Book requested successfully. Waiting for admin approval.']);
    } catch (Exception $e) {
        $pdo->rollBack();
        echo json_encode(['success' => false, 'message' => 'Failed to request book: ' . $e->getMessage()]);
    }

} elseif ($action === 'approve') {
    // Admin approves a request
    $transaction_id = $data['transaction_id'];

    $stmt = $pdo->prepare("SELECT * FROM transactions WHERE id = ? AND status = 'requested'");
    $stmt->execute([$transaction_id]);
    $transaction = $stmt->fetch();

    if (!$transaction) {
        echo json_encode(['success' => false, 'message' => 'Request not found or already processed']);
        exit;
    }

    // Check availability again
    $stmt = $pdo->prepare("SELECT available FROM books WHERE id = ?");
    $stmt->execute([$transaction['book_id']]);
    $book = $stmt->fetch();

    if ($book['available'] < 1) {
        echo json_encode(['success' => false, 'message' => 'Book is out of stock, cannot approve']);
        exit;
    }

    $pdo->beginTransaction();
    try {
        // Update Transaction to 'issued' and update dates
        $issue_date = date('Y-m-d');
        $due_date = date('Y-m-d', strtotime('+14 days'));

        $stmt = $pdo->prepare("UPDATE transactions SET status = 'issued', issue_date = ?, due_date = ? WHERE id = ?");
        $stmt->execute([$issue_date, $due_date, $transaction_id]);

        // Decrease Availability
        $stmt = $pdo->prepare("UPDATE books SET available = available - 1 WHERE id = ?");
        $stmt->execute([$transaction['book_id']]);

        $pdo->commit();
        echo json_encode(['success' => true, 'message' => 'Request approved successfully']);
    } catch (Exception $e) {
        $pdo->rollBack();
        echo json_encode(['success' => false, 'message' => 'Failed to approve: ' . $e->getMessage()]);
    }

} elseif ($action === 'reject') {
    // Admin rejects a request
    $transaction_id = $data['transaction_id'];

    $stmt = $pdo->prepare("UPDATE transactions SET status = 'rejected' WHERE id = ? AND status = 'requested'");
    if ($stmt->execute([$transaction_id])) {
        echo json_encode(['success' => true, 'message' => 'Request rejected']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to reject request']);
    }

} elseif ($action === 'return') {
    $student_id = $data['student_id'];
    $book_id = $data['book_id']; // Transaction might need book_id or transaction id. Let's assume we find active transaction.

    // Find active transaction
    // If book_id is passed, we look for an issued transaction for this book and student
    // Ideally we should pass transaction ID, but let's support book_id for simplicity if UI sends it

    $query = "SELECT id, book_id FROM transactions WHERE student_id = ? AND status = 'issued'";
    $params = [$student_id];

    if ($book_id) {
        $query .= " AND book_id = ?";
        $params[] = $book_id;
    }
    // If multiple copies of same book? Logic holds, just return one.

    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $transaction = $stmt->fetch();

    if (!$transaction) {
        echo json_encode(['success' => false, 'message' => 'No active record found for this return']);
        exit;
    }

    $pdo->beginTransaction();
    try {
        // Update Transaction
        $return_date = date('Y-m-d');
        $stmt = $pdo->prepare("UPDATE transactions SET return_date = ?, status = 'returned' WHERE id = ?");
        $stmt->execute([$return_date, $transaction['id']]);

        // Increase Availability
        $stmt = $pdo->prepare("UPDATE books SET available = available + 1 WHERE id = ?");
        $stmt->execute([$transaction['book_id']]);

        $pdo->commit();
        echo json_encode(['success' => true, 'message' => 'Book returned successfully']);
    } catch (Exception $e) {
        $pdo->rollBack();
        echo json_encode(['success' => false, 'message' => 'Failed to return book']);
    }

} elseif ($action === 'history') {
    // If student_id is provided, show their history. If not (and presumably admin), show all or filtered.
    // For now, let's keep it simple.

    $query = "
        SELECT t.*, b.title, b.author, b.isbn, s.name as student_name
        FROM transactions t
        JOIN books b ON t.book_id = b.id
        LEFT JOIN students s ON t.student_id = s.student_id
        WHERE 1=1
    ";
    $params = [];

    if (isset($_GET['student_id'])) {
        $query .= " AND t.student_id = ?";
        $params[] = $_GET['student_id'];
    }

    if (isset($_GET['status'])) {
        $query .= " AND t.status = ?";
        $params[] = $_GET['status'];
    }

    $query .= " ORDER BY t.created_at DESC";

    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $history = $stmt->fetchAll();

    echo json_encode($history);
}
?>
