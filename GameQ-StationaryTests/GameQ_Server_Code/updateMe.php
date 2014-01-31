<?php
    include "connect.php";
    include "methods.php";
    
    if (chkLogin($dbConnection))
    {
        
        
        if(isset($_POST["losenord"], $_POST["email"], $_POST["country"], $_POST["secretQ"], $_POST["secret"]))
        {
            $password = $_POST["losenord"];
            if(login($email, $password, $dbConnection))
            {
                //login code
                $password = $_POST["nyttLosenord"];
                $email = $_POST["email"];
                $country = $_POST["country"];
                $secretQ = $_POST["secretQ"];
                $secret = $_POST["secret"];
                
                if ($password != "")
                {
                    $password = $_POST["nyttLosenord"];
                    $rndSalt = hash("sha512", uniqid(mt_rand(1, mt_getrandmax()), true));
                    $password = hash("sha512", $password.$rndSalt);
                    
                    if ($inStmt = $dbConnection->prepare("UPDATE users SET salt = ?, password = ? WHERE id = ? LIMIT 1"))
                    {
                        $inStmt->bind_param("ssi", $rndSalt, $password, $userID);
                        $inStmt->execute();
                    }
                }
                if ($email != "")
                {
                    if ($inStmt = $dbConnection->prepare("UPDATE users SET email = ? WHERE id = ? LIMIT 1"))
                    {
                        $inStmt->bind_param("ss", $email, $userID);
                        $inStmt->execute();
                    }
                }
                if ($country != "")
                {
                    if ($inStmt = $dbConnection->prepare("UPDATE users SET country = ? WHERE id = ? LIMIT 1"))
                    {
                        $inStmt->bind_param("ss", $country, $userID);
                        $inStmt->execute();
                    }
                }
                if ($secretQ != "")
                {
                    if ($inStmt = $dbConnection->prepare("UPDATE users SET secret = ?, secretQ = ? WHERE id = ? LIMIT 1"))
                    {
                        $inStmt->bind_param("sss", $secret, $secretQ, $userID);
                        $inStmt->execute();
                    }
                }
                echo "updated me";
                
                
                
            }
            else
            {
                //failed login code
                echo "wrongpassword";
            }
        }
        else
        {
            //Invalid Post Data
            echo "no";
        }
        
        
    }
    else
    {
        echo "badsession";
    }
    

?>