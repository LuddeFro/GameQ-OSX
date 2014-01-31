<?php
    
    include "connect.php";
    include "methods.php";
    
    secureSessionStart();
    
    if(isset($_POST["email"], $_POST["losenord"]))
    {
        $email = $_POST["email"];
        $password = $_POST["losenord"];
        if(login($email, $password, $dbConnection))
        {
            //login code
            echo "sign in success";
        }
        else
        {
            //failed login code
            header("Location: ./login.php?error=1");
            echo "sign in failed";
        }
    }
    else
    {
        //Invalid Post Data
        echo "no";
    }

    

?>