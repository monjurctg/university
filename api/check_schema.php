<?php
require_once 'config.php';

try {
    $stmt = $pdo->query("SHOW COLUMNS FROM transactions LIKE 'status'");
    $column = $stmt->fetch();
    print_r($column);
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage();
}
?>
