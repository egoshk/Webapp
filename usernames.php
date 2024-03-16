<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<body>
<table border="1" align="center">
<tr>
  <td>User ID</td>
  <td>First Name</td>
  <td>Last Name</td>
  <td>Date of Birth</td>
  <td>Street</td>
  <td>City</td>
  <td>Postal Code</td>
  <td>Phone</td>
  <td>Email</td>
  <td>Username</td>
  <td>Password</td>
  
</tr>
<?php
//Call the script that connects to the database   
include('connectdb.php'); 
$query = mysqli_query($dbconnect, "SELECT * FROM user_info")
   or die (mysqli_error($dbconnect));
while ($row = mysqli_fetch_array($query)) {
  echo
   "<tr>
    <td>{$row['user_id']}</td>
    <td>{$row['first_name']}</td>
    <td>{$row['last_name']}</td>
    <td>{$row['date_of_birth']}</td>
    <td>{$row['street']}</td>
    <td>{$row['city']}</td>
    <td>{$row['postal_code']}</td>
    <td>{$row['phone']}</td>
    <td>{$row['email']}</td>
    <td>{$row['username']}</td>
    <td>{$row['password']}</td>
   </tr>\n";
}
?>
</table>
</body>
</html>
