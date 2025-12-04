<?php
require_once 'config.php';

try {
    $pdo->exec("ALTER TABLE transactions MODIFY COLUMN status ENUM('requested', 'issued', 'returned', 'overdue', 'rejected') NOT NULL DEFAULT 'requested'");
    echo "Database schema updated successfully! You can now request books.";
} catch (PDOException $e) {
    echo "Error updating schema: " . $e->getMessage();
}
?>
