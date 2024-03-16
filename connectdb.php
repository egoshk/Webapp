<?php
$hostname = "localhost";
$username = "root";
$password = "root";
$db = "election_calgary";
$dbconnect=mysqli_connect($hostname,$username,$password,$db);
if($dbconnect->connect_error) {
  die("Database connection failed: ".$dbconnect->connect_error);
}
?>
