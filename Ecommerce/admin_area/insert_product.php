<!DOCTYPE>
<?php 
include ("includes/db.php");
?>
<html>
    <head>
        <title>Inserting Product</title>
        <script src="https://cloud.tinymce.com/stable/tinymce.min.js"></script>
        <script>tinymce.init({ selector:'textarea' });</script>
        </script>
    </head>
<body >

    <form action="insert_product.php" method="post" enctype="multipart/form-data">

        <table align="center" width="700" border="1" bgcolor="bluesky" >
            <tr>
                <td colspan="8"><h2 align="center">Insert your Prodcut here</h2></td>
            </tr>
            <tr>
                <td align="right">Product Title</td>
                <td align="center" ><input type="text" name="product_title"  size="60"/></td>
            </tr>
            <tr>
                <td align="right">Product Brand</td>


                <td align="center">
                    <select name="product_brand">
                        <option> Select a Product Brand </option>

                        <?php 
                        $get_brands = " SELECT * FROM brands";
                        /* Sending Query to DB*/

                        $result = $mysqli->query($get_brands);
                        //                             printf("Select returned %d rows.\n", $result);

                        while ($row_brands =mysqli_fetch_array($result))
                        {


                            $brand_id=$row_brands['brand_id'];
                            $brand_title=$row_brands['brand_title'];
                            echo "<option value='$brand_id'>$brand_title</option>";

                        }


                        ?>

                    </select>
                </td>
            </tr>

            <tr>

                <td align="right">Product Category</td>
                <td align="center">
                    <select name="product_cat">
                        <option > Select a Product Category </option>

                        <?php 
                        $get_cats = " SELECT * FROM categories";
                        /* Sending Query to DB*/

                        $result = $mysqli->query($get_cats);
                        //                             printf("Select returned %d rows.\n", $result);

                        while ($row_cats =mysqli_fetch_array($result))
                        {


                            $cat_id=$row_cats['cat_id'];
                            $cat_title=$row_cats['cat_title'];
                            echo "<option value='$cat_id'>$cat_title</option>";

                        }


                        ?>

                    </select>
                </td>
            </tr>
            <tr>
                <td  align="right">Product Image</td>
                <td align="center" ><input type="file" name="product_image" /></td>
            </tr>
            <tr>
                <td  align="right">Product Price</td>
                <td align="center" ><input type="text" name="product_price" size="60" /></td>
            </tr>
            <tr>
                <td  align="right" >Product Desc</td>
                <td align="center" ><textarea  name="product_desc" cols="20" rows="10"> </textarea> </td>
            </tr>
            <tr>
                <td  align="right">Product Keywords</td>
                <td align="center" ><input type="text" name="product_keywords" size="60" /></td>
            </tr>
            <tr align="center">

                <td  colspan="8"><input type="submit" name="insert_post" value="Submit" size="60" /></td>
            </tr>
        </table>

    </form>
</body>
</html>




<?php 


//checking if the button " Submit was clicked
if (isset($_POST['insert_post']))  {

    $product_title=$_POST['product_title'];
    $product_brand=$_POST['product_brand'];
    $product_cat=$_POST['product_cat'];
    $product_price=$_POST['product_price'];
    $product_description=$_POST['product_desc'];
  
    $product_keywords=$_POST['product_keywords'];

    $product_image=$_FILES['product_image']['name'];
  
    $product_image_tmp=$_FILES['product_image']['tmp_name'];

   $product_insert="insert into products (product_cat,product_brand, product_title, product_price, product_desc, product_img, product_keywords)
 values ('$product_cat','$product_brand','$product_title','$product_price','$product_description','$product_image','$product_keywords' )";

//    move_uploaded_file($product_image_tmp,"images/$product_image");
    
     if (!move_uploaded_file($product_image_tmp,"images/$product_image")){
        echo "<P>MOVE UPLOADED FILE FAILED!</P>";
         print_r(error_get_last()); 
     }
      
   
    
    $success=$mysqli->query($product_insert);
    
    if ($success)
    {
        echo "<script>alert('The Product Was added successfully')</script>";
        echo "<script>window.open('insert_product.php','_self')</script>";
    }
    else {
        echo mysqli_error($mysqli); 
        echo "insertion to db not worked";
    
    }
}


?>


