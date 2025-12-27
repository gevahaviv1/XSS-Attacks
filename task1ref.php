<?php
session_start();
$flag = getenv('REF_FLAG');
//setcookie('refauth', $flag, time() + 3600);
?>
<!DOCTYPE html>
<html>
<head><title>Grades Portal - Home</title></head>
<body>
  <h2>Welcome!</h2>
  <p>There are no new messages, please come back again later!</p>

<?php
if (isset($_GET['msg'])) {
echo "<p>Message: " . $_GET['msg'] . "</p>";
}
?>

</body>
</html>

