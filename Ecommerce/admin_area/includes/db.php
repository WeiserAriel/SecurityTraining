<?php 

$mysqli=mysqli_connect("localhost","root","","eccomerce");

if (!$mysqli){
    echo "Fail to Connect to Mysqli". mysqli_connect_errno();
}
?>