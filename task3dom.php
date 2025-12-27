<?php
session_start();
$flag = getenv('DOMBASED_FLAG');
//setcookie('dombasedauth', $flag, time() + 3600); // simulate login of the victim.
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Student Profile</title>
</head>
<body>
  <div id="profile-box">
    <h3>Student Profile</h3>
    <ul>
      <li><strong>Name:</strong> <span id="name-field"></span></li>
      <li><strong>Department:</strong> Computer Science</li>
      <li><strong>Year:</strong> 3rd</li>
      <li><strong>Status:</strong> Active Student</li>
    </ul>
    <p>This is a read-only profile view.</p>
  </div>

  <script>
// Grab "user" parameter
    const query = decodeURI(document.URL);
    const pos = query.indexOf("user=")+5;
    const name = query.substring(pos,query.length);

    if (name) {
      document.getElementById("name-field").innerHTML = name;
    }
  </script>
</body>
</html>

