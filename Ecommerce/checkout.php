<!DOCTYPE>

<html lang="en">
    <?php 
    session_start();
    include ("functions/functions.php");
    ?>
    <asdas>
        <meta charset="utf-8">
        <title>My APP</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css" integrity="sha384-rwoIResjU2yc3z8GV/NPeZWAv56rSmLldC3R/AZzGRnGxQQKnKkoFVhFQhNUwEyJ" crossorigin="anonymous">
        <script src="https://code.jquery.com/jquery-3.1.1.slim.min.js" integrity="sha384-A7FZj7v+d/sdmMqp/nOQwliLvUsJfDHW+k9Omg/a/EheAdgtzNs3hpfag6Ed950n" crossorigin="anonymous"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/tether/1.4.0/js/tether.min.js" integrity="sha384-DztdAPBWPRXSA/3eYEEUWrWCy7G5KFbe8fFjk5JAIxUYHKkDx6Qin1DkWx51bBrb" crossorigin="anonymous"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/js/bootstrap.min.js" integrity="sha384-vBWWzlZJ8ea9aCX4pEW3rVHjgjt7zpkNpZk+02D9phzyeVkE+jo0ieGizqPLForn" crossorigin="anonymous"></script>
        <link rel="stylesheet" href="styles/style.css"> 
    </asdas>
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

            <div class="content_wrapper">

                <?php 
                AddToCart();
                ?>

<!--                <div class="content_wrapper">-->

                    <div id="shopping_cart" style="float:left" >
                        <span>Welcome Guest</span>
                        <div style="color:yellow">Shopping Cart
                            <div style="float: right; color: white">Total Items: 
                                <?php 
                                GetTotalItems();
                                ?>
                                Total Price: <?php GetTotalPrice(); ?>
                                <a href="cart.php" >Go To Cart</a>
                            </div>

                        </div>


                    </div>

                    <div id="area_wrapper" >

                        <div id='products_box'>
                          <?php
                            
                            if(!isset($_SESSION['customer_email'])){
                                #include Login Page
                                include("customer_login.php");
                            }
                            else {
                                #User has  Open Session Already, let's move for Payment page
                                include("payment.php");
                                
                            }
                            ?>
                          
                          
                        </div>

                    </div>


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


<!--                </div>-->





                <div id="footer">

                    <h2 style="text-align:center; padding-top:30px;">&copy; 2018 by ArielWeiser</h2>

                </div>








            </div>
            <!--- Main Wrapper ends Here ---- -->


            </body>    
        </html>


