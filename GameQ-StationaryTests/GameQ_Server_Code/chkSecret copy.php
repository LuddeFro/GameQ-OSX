<?php
    include "connect.php";
    
    if (isset($_POST["secret"], $_POST["secretQ"], $_POST["email"]))
    {
        if ($secStmt = $dbConnection->prepare("SELECT secret FROM users WHERE secretQ = ? AND email = ? LIMIT 1"))
        {
            $secStmt->bind_param("ss", $_POST["secretQ"], $_POST["email"]);
            $secStmt->execute();
            $secStmt->store_result();
            $secStmt->bind_result($secret);
            $secStmt->fetch();
            
            if ($secStmt->num_rows == 1)
            {
                if ($secret == $_POST["secret"])
                {
                    $tmpPass = rand(10000, 30000);
                    $password = md5($tmpPass);
                    $rndSalt = hash("sha512", uniqid(mt_rand(1, mt_getrandmax()), true));
                    $password = hash("sha512", $password.$rndSalt);
                    
                    if ($deacStmt = $dbConnection->prepare("UPDATE users SET password = ?, salt = ? WHERE secretQ = ? AND email = ? LIMIT 1"))
                    {
                        $deacStmt->bind_param("ssss", $password, $rndSalt, $_POST["secretQ"], $_POST["email"]);
                        $deacStmt->execute();
                        $msg = "Your password to GameQ has been reset. You should log in and change your password as soon as possible. Please use the following temporary password to login:/r/n /r/n" . $tmpPass;
                        $msg = wordwrap($msg, 70, "/r/n");
                        $to = $_POST["email"];
                        $subject = "GameQ || Password Reset";
                        mail($to, $subject, $msg);
                        echo "pwdreset";
                    }
                    else
                        echo "no";
                }
                else
                    echo "wrongsecret";
            }
            else
                echo "no";
        }
        else
            echo "no";
    }
    else
        echo "no";
?>