<?php
session_start();
// Database connection using environment variables
$host = getenv('DB_HOST');
$username = getenv('DB_UNAME'); 
$password = getenv('DB_PASSWORD'); 
$database = getenv('DB_NAME'); 

$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $comment = $_POST['comment'] ?? '';
    $stmt = $conn->prepare("INSERT INTO comments (comment) VALUES (?)");
    $stmt->bind_param("s", $comment);
    $stmt->execute();
    $stmt->close();
}

// Close the connection
$conn->close();
?>

<!DOCTYPE html>
<html>
<head><title>Course Feedback Forum</title></head>
<body>
    <h2>Leave Anonymous Comment</h2>
    <form method="POST">
        <textarea name="comment" rows="4" cols="50" placeholder="Enter Question here"></textarea><br>
        <button type="submit">Submit</button>
    </form>
</body>
</html>

