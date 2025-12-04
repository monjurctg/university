<?php
require_once 'config.php';

$type = $_GET['type'] ?? 'admin';

if ($type === 'admin') {
    // Admin Stats
    $stats = [];

    $stmt = $pdo->query("SELECT COUNT(*) as count FROM books");
    $stats['total_books'] = $stmt->fetch()['count'];

    $stmt = $pdo->query("SELECT COUNT(*) as count FROM students"); // Assuming members are students
    $stats['total_members'] = $stmt->fetch()['count'];

    $stmt = $pdo->query("SELECT COUNT(*) as count FROM transactions WHERE status = 'issued'");
    $stats['books_issued'] = $stmt->fetch()['count'];

    echo json_encode($stats);

} elseif ($type === 'student') {
    // Student Stats
    $student_id = $_GET['student_id'] ?? '';
    $stats = [];

    if ($student_id) {
        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM transactions WHERE student_id = ? AND status = 'issued'");
        $stmt->execute([$student_id]);
        $stats['issued_books'] = $stmt->fetch()['count'];

        // Pending returns (issued books) - same as issued for now, or could check due date
        $stats['pending_returns'] = $stats['issued_books'];

        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM transactions WHERE student_id = ?");
        $stmt->execute([$student_id]);
        $stats['total_borrowed'] = $stmt->fetch()['count'];
    }

    echo json_encode($stats);
}
?>
