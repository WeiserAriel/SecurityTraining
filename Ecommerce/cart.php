<!DOCTYPE>

<html lang="en">
    <?php 
    include ("functions/functions.php");
    session_start();
    ?>

    <meta charset="utf-8">
    <title>Document</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css" integrity="sha384-rwoIResjU2yc3z8GV/NPeZWAv56rSmLldC3R/AZzGRnGxQQKnKkoFVhFQhNUwEyJ" crossorigin="anonymous">
    <script src="https://code.jquery.com/jquery-3.1.1.slim.min.js" integrity="sha384-A7FZj7v+d/sdmMqp/nOQwliLvUsJfDHW+k9Omg/a/EheAdgtzNs3hpfag6Ed950n" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/tether/1.4.0/js/tether.min.js" integrity="sha384-DztdAPBWPRXSA/3eYEEUWrWCy7G5KFbe8fFjk5JAIxUYHKkDx6Qin1DkWx51bBrb" crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/js/bootstrap.min.js" integrity="sha384-vBWWzlZJ8ea9aCX4pEW3rVHjgjt7zpkNpZk+02D9phzyeVkE+jo0ieGizqPLForn" crossorigin="anonymous"></script>
    <link rel="stylesheet" href="styles/style.css"> 

    <body>

        <!--- Main Wrapper Starts Here ---- -->
        <div class="mian_wrapper">
            <!--- Header Wrapper Starts Here ---- -->
            <div class="header_wrapper">
                <a href="index.php">
                    <img id="banner"  src="images/banner1.jpg" alt="Banner">
                    <img id="logo" src="images/logo.jpg">
                </a>
            </div>

            <!--- Header Wrapper ends Here ---- -->

            <!--- Menubar starts here ---- -->
            <div class="menubar">

                <div id="menu">
                    <ul>
                        <li><a href="index.php?all_products=1">All Products</a></li>
                        <li><a href="contact_us.php">Contact US</a></li>
                        <li><a href="/customer/my_account.php">My Account</a></li>
                        <li><a href="#">Sign Up</a></li>
                        <li><a href="#">All Products</a></li>
                    </ul>

                </div>

                <div class="form">

                    <form method="get" action="result.php" enctype="multipart/form-data">
                        <input type="text" name="user_query" placeholder="Search a Product">
                        <input type="submit" name="Submit" value="Submit">

                    </form>
                </div>

            </div>
            <!--- Menubar ends here ---- -->

            <!--Content wrapper start -->
            <div class="content_wrapper">

                <?php 
                AddToCart();
                ?>


                <!--shopping_cart start here -->
                <div id="shopping_cart" style="float:left" >
                      <?php 
                        if(isset($_SESSION['customer_email'])){
                            $email=$_SESSION['customer_email'];
                            echo "<b> Hello . $email</b> ";
                        }
                        else{
                              echo "<span>Welcome Guest</span>";
                        }
                        ?>
                    <div style="color:yellow">
                        <div style="float: right; color: white">Total Items: 
                            <?php 
                            GetTotalItems();
                            ?>
                            Total Price: <?php GetTotalPrice(); ?>
                            <a href="index.php" >Back</a>
                        </div>

                    </div>


                </div>  
                <!--shopping_cart end here -->


                <!---  area_wrapper starts ---- -->

                <div id="area_wrapper" align="center" >

                    <form action="" method="post" enctype="multipart/form-data">

                        <table style="width:800px;">

                            <tr align="center">
                                <th style="margin-right:15px;align:center" ><h4>Remove</h4></th>
                                <th style="margin-right:15px;align:center"><h4>Products</h4></th>    
                                <th style="margin-right:15px;align:center"><h4>Quantity</h4></th>    
                                <th style="margin-right:15px;align:center"><h4>Total Price </h4></th>         
                            </tr>

                            <?php  
                            //                           echo "start GetProductsFromCart()";

                            GetProductsFromCart(); 
                            ?>

                            <?php 



                            /*Checking if remove checkbox was set */
                            if(isset($_POST['update_cart'])){
                               


                                $ip=get_client_ip();


                                if (empty($_POST['remove']) &&  empty($_POST['quantity']) ){
                                    // No checkbox was picked, go back to cart.php
                                    echo "<script>window.open('cart.php','_self')</script>";

                                }
                                else{


                                    if (!empty($_POST['remove'])){
//                                         echo "Get inside 'remove'";
                                        foreach ($_POST['remove'] as $remove_id){
                                            //$remove_id becomes the product_id

                                            $delete_query="delete from cart where p_id='$remove_id' and ip_add='$ip'";



                                            $result = $mysqli->query($delete_query);
                                            if (!$result)
                                            {
                                                echo "<h2>Can't remove products</h2>";
                                            }
                                            //                                else {
                                            //                                    echo "<script>window.open('cart.php','_self')</script>";
                                            //                                }




                                        }
                                    }
                                    // Check if the Quantity of the product was updated ( and update DB if so)
                                    $pidarr=array();
                                    foreach ($_POST['pid'] as $pid)
                                    {
                                        array_push($pidarr, $pid);
                                    }
                                    
                                    $i = 0;
                                    foreach ($_POST['quantity'] as $qny)
                                    {    
                                        if (!empty($qny))
                                        {
                                            $ip=get_client_ip();
                                            $insert_query="UPDATE cart SET quantity=$qny WHERE ip_add='$ip' AND p_id=$pidarr[$i]";
                                            $result = $mysqli->query($insert_query);
                                            if (!$result)
                                            {
                                                echo "<h2>$mysqli->error</h2>";
                                            }

                                            $_SESSION['quantity']=$qny;
                                        }
                                        $i++;
                                    }
                                }
                                echo "<script>window.open('cart.php','_self')</script>";
                                
                            }
                            ?>

                            <?php 
                            if(isset($_POST['continue'])){
                                echo "<script>window.open('index.php','_self')</script>";
                            }
                            ?>


                        </table>


                    </form>






                </div>







                <!---  sidebar start here ---- -->
                <div id="sidebar">

                    <div id="sidebar_title">Categories</div>

                    <div id="cats">
                        <ul>


                            <?php 
                            GetAllCat();

                            ?>



                        </ul>


                    </div>
                    <div id="sidebar_title">Brands</div>

                    <div id="cats">
                        <ul>

                            <?php 
                            GetAllBrand();
                            ?>



                        </ul>


                    </div>



                </div>
                <!---  sidebar end here ---- -->




            </div>
            <!--Content wrapper closed -->


            <!--fotter start here -->
            <div id="footer">

                <h2 style="text-align:center; padding-top:30px;">&copy; 2018 by ArielWeiser</h2>

            </div>
            <!--fotter end here -->








        </div>
        <!--- Main Wrapper ends Here ---- -->


    </body>    
</html>


