<?php

//establish conection with DB:
//$con=mysql_connect("localhost","root","","eccomerce");
$mysqli = mysqli_connect("localhost","root","","eccomerce");

/* check connection */
if ($mysqli->connect_errno) {
    printf("Connect failed: %s\n", $mysqli->connect_error);
    exit();
}

//get all categories from DB:
function GetAllCat (){
    global $mysqli;


    //    if (!isset($_GET['cat'])){
    //        if(!isset($_GET['brand'])){

    $get_cats = " SELECT * FROM categories";
    /* Sending Query to DB*/

    $result = $mysqli->query($get_cats);
    if ( $result === 0)
    {
        printf("Select returned %d rows.\n", $result);
    }


    //    $run_cats = mysqli_db_query($mysqli,$get_cats);
    //   mysqli::query()
    //  $run_cats = mysqli_query($con,$get_cats);


    while ($row_cats =mysqli_fetch_array($result))
    {


        $cat_id=$row_cats['cat_id'];
        $cat_title=$row_cats['cat_title'];
        echo "<a href ='index.php?cat=$cat_id''><li>$cat_title</li></a>";

    }
  
}

function GetAllBrand (){
    global $mysqli;
    $get_brands = " SELECT * FROM brands";

    /*** Sending Query to DB ***/

    $result = $mysqli->query($get_brands);
    if ( $result === 0)
    {
        printf("Select returned %d rows.\n", $result);
    }


    //    $run_cats = mysqli_db_query($mysqli,$get_cats);
    //   mysqli::query()
    //  $run_cats = mysqli_query($con,$get_cats);


    while ($row_brands =mysqli_fetch_array($result))
    {


        $brand_id=$row_brands['brand_id'];
        $brand_title=$row_brands['brand_title'];
        echo "<a href ='index.php?brand=$brand_id'><li>$brand_title</li></a>";

    }
}
function GetPro(){

    global $mysqli;    
    if(isset($_GET['cat'])){
        $cat_id=$_GET['cat'];
        $get_pro="SELECT * FROM products WHERE product_cat='$cat_id'";

    }
    else if (isset($_GET['brand'])){
        $brand_id=$_GET['brand'];
        $get_pro="SELECT * FROM products WHERE product_brand='$brand_id'";
    }
    else if(isset($_GET['all_products'])) {
        $all_products=$_GET['all_products'];
        $get_pro="SELECT * FROM products";
    }
    else{
        $get_pro="SELECT * FROM products ORDER BY RAND() LIMIT 0,6";
    }

    $result = $mysqli->query($get_pro);
    if (!$result){
        echo "Error in SQL:" + mysqli_error($mysqli); 
    }
    if ($result->num_rows == 0 )
    {
        echo "<h1>There are no Products available</h1>";
    }

    while ($row =mysqli_fetch_array($result)) {

        $product_id=$row['product_id'];
        $product_cat=$row['product_cat'];
        $product_brand=$row['product_brand'];
        $product_title=$row['product_title'];
        $product_price=$row['product_price'];
        $product_image=$row['product_img'];

        echo "<div id='single_product' >
                <h3  >$product_title</h3>
                <img src='admin_area/images/$product_image' width='180px' height='180px' />    
                <p>price:<b> $product_price<b></p>
                <a href='details.php?product_id=$product_id' style='float:left' class='btn btn-info' >Details</a>
                <a href='index.php?add_cart=$product_id' style='float:right' ><button class='btn btn-success' >Add To Cart</button></a>
            </div>";

    }



}

function AddToCart(){

    global $mysqli;
    if(isset($_GET['add_cart'])){
        $product_id=$_GET['add_cart'];
        $ip=get_client_ip();
        if (!$ip){
            echo"Can't get Client IP";
            exit();
        }

        //Make sure the product is not already in cart
        $query="SELECT * from cart WHERE ip_add='$ip' AND p_id='$product_id'";
        $result = $mysqli->query($query);
        if ( $result->num_rows > 0)
        {
            echo"";
        }
        else {
            //Need to insert into cart table
            $insert="INSERT INTO cart (p_id,ip_add,quantity) values ('$product_id','$ip','1')";
            $result = $mysqli->query($insert);
            if (!$result){
                echo "Error in INSERT SQL:" + mysqli_error($mysqli); 
            }

            echo "<script>window.open('index.php','_self')</script>";
        }
    }

}


function GetTotalItems(){
    global $mysqli;
    $ip=get_client_ip();
    if (!$ip){
        echo"Can't get Client IP";
        exit();
    }
    $query="SELECT * from cart WHERE ip_add='$ip'";
    $result = $mysqli->query($query);
    echo $result->num_rows;

}


function GetTotalPrice(){

    global $mysqli;
    $ip=get_client_ip();
    if (!$ip){
        echo"Can't get Client IP";
        exit();
    }
    $query="SELECT * from cart WHERE ip_add='$ip'";
    $result = $mysqli->query($query);
    //    echo "Num of res " . $result->num_rows ;


    $totalPrice=0;

    while ($row =mysqli_fetch_array($result)) {    
        //        printf ("%d %s\n", $row[0], $row[1],$row[2]);
        $product_id=$row['p_id'];
        //        echo "First product_id is" . $product_id;
        //Get price of specific item:
        $query="SELECT * from products WHERE product_id='$product_id'";
        $result_obj = $mysqli->query($query);
        $current_row= mysqli_fetch_array($result_obj);
        if ($current_row){
            $current_price=$current_row['product_price'];
            //            echo "First product_price is" . $current_price;
            $totalPrice= $totalPrice +$current_price;
        }


    }
    echo $totalPrice;
}

// Function to get the client IP address
function get_client_ip() {
    $ipaddress = '';
    if (getenv('HTTP_CLIENT_IP'))
        $ipaddress = getenv('HTTP_CLIENT_IP');
    else if(getenv('HTTP_X_FORWARDED_FOR'))
        $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
    else if(getenv('HTTP_X_FORWARDED'))
        $ipaddress = getenv('HTTP_X_FORWARDED');
    else if(getenv('HTTP_FORWARDED_FOR'))
        $ipaddress = getenv('HTTP_FORWARDED_FOR');
    else if(getenv('HTTP_FORWARDED'))
        $ipaddress = getenv('HTTP_FORWARDED');
    else if(getenv('REMOTE_ADDR'))
        $ipaddress = getenv('REMOTE_ADDR');
    else
        $ipaddress = 'UNKNOWN';
    return $ipaddress;
}

function GetProductSearch(){
    global $mysqli;

    if(isset($_GET['submit'])){
        if (isset($_GET['user_query'])){
            $user_query=$_GET['user_query'];
            $get_pro="SELECT * from products WHERE product_keywords  LIKE '%$user_query%'";
        }
        else {
            exit();
        }






        $result = $mysqli->query($get_pro);
        if (!$result){
            echo "Error in SQL:" + mysqli_error($mysqli); 
        }
        if ($result->num_rows == 0 )
        {
            echo "<h1>There are no Products available</h1>";
        }

        while ($row =mysqli_fetch_array($result)) {

            $product_id=$row['product_id'];
            $product_cat=$row['product_cat'];
            $product_brand=$row['product_brand'];
            $product_title=$row['product_title'];
            $product_price=$row['product_price'];
            $product_image=$row['product_img'];

            echo "<div id='single_product' >
                <h3  >$product_title</h3>
                <img src='admin_area/images/$product_image' width='180px' height='180px' />
                <div class='single_product_btn'>
                    <p>price:<b> $product_price<b></p>
                    <a href='details.php?product_id=$product_id' style='float:left' class='btn btn-info' >Details</a>
                    <a href='index.php?product_id=$product_id' style='float:right' ><button class='btn btn-success' >Add To Cart</button></a>
                </div>
            </div>";

        }
    }


}


function  GetProductsFromCart(){

    global $mysqli;
    $ip=get_client_ip();
    if (!$ip){
        echo"Can't get Client IP";
        exit();
    }


    /*
        SELECT column_name(s)
    FROM table1
    INNER JOIN table2 ON table1.column_name = table2.column_name;
    */
    // Get All products from Cart where ip_add == $ip ( INNER Join with products)
    $query= "SELECT * FROM cart INNER JOIN products where cart.p_id=products.product_id AND cart.ip_add='$ip'";

    //    echo "<h1>$query</h1>";
    $result = $mysqli->query($query);
    // Checking the Cart is empty
    if (empty($result))
    {
        echo "<br><h1>You Have No Items in Your Cart!</h1>";

    }
    //Get information of each product in cart and display it in "content area":
    else{
        $totalPrice=0;
        while ($row= mysqli_fetch_array($result)){

            $product_image=$row['product_img'];
            $proudct_price=$row['product_price'];
            $product_quantity=$row['quantity'];
            $product_title  =$row['product_title'];
            $product_id=$row['product_id'];
            if($product_quantity>0){
                $proudct_price*=$product_quantity;
            }
            $totalPrice+=$proudct_price;

            echo "
            <tr>
                <td align='center'><input type='checkbox' name='remove[]' value='$product_id'></td>
                <td align='left' colspan='1'>$product_title<br>
                    <img src='admin_area/images/$product_image'  height='60' width='60'>
                </td>

                <td align='left' colspan='2' >
                    <input type='text' size='2' name='quantity[]' value='$product_quantity' >
                    <input type='hidden' name='pid[]' value='$product_id'>
                </td>

                <td align='left' colspan='3'>$proudct_price</td>

            </tr>

            ";




        }
        //Print Total Sub Total:
        echo "

          <tr>
                <td align='right' colspan='4'><b>Total price is: $totalPrice</b></td>
            </tr>
            <tr>
                <td style='padding:50'><input type='submit' name='update_cart' value='Update Cart' /></td>

                 <td style='padding:50'><input type='submit' name='continue' value='Continue Shopping' /></td>

                  <td style='padding:50'><form> <button formaction='checkout.php'>CheckOut</button></form></td>

            </tr>


        ";


    }


}


function  UpdateCart(){


}

function RemoveFromCart(){

    // Remove from cart it 'remove_cart' isset
}


?>


