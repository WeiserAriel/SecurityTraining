<?php
#session_start();
#include ("functions/functions.php");
?>
<div>
    <form method="post" >
        <table width="500" align="center" bgcolor="skyblue">
            <tr>
                <td colspan="4" align="center">
                    <h2>Login or Register to Buy</h2>
                </td>
            </tr>
            <br>
            <tr>
                <td><b>Emal:</b></td>
                <td><input type=text name='email' placeholder='Enter Your Email' required</td>

            </tr>
            <br>
            <tr>
                <td><b>Password:</b></td>
                <td><input type=password name='pass' placeholder='Enter Your Password' required</td>
            </tr>

            <tr>

                <td align="left"><input type="submit" name="login" value="login"</td>
            </tr>


        </table>
        <h2 style="float:left; padding:5px"><a href="customer_register.php">Click for Registeration</a></h2>
    </form>

</div>
<?php

if(isset($_POST['login'])){
    $c_email=$_POST['email'];
    $c_pass=$_POST['pass'];


    $query="SELECT * FROM customers WHERE customer_email='$c_email' AND customer_pass='$c_pass'";

    $result = $mysqli->query($query);
    if ($result->num_rows == 0){
        echo "<script>alert('Password or Email were not correct! Please try Again')</script>";
    }
    else {
        #Start Session
        $_SESSION['customer_email']=$c_email;
         echo "<script>alert('Login Successfully ! Move to Index.php')</script>";
        echo "<script>window.open('index.php','_self')</script>";
    }
}

?>