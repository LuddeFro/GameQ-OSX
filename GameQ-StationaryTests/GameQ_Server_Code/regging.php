<?php
    include "connect.php";
    include "methods.php";
    $password = $_POST["losenord"];
    $rndSalt = hash("sha512", uniqid(mt_rand(1, mt_getrandmax()), true));
    $password = hash("sha512", $password.$rndSalt);
    
    if ($chkStmt = $dbConnection->prepare("SELECT email FROM users WHERE email = ? LIMIT 1"))
    {
        $chkStmt->bind_param($_POST["email"]);
        $chkStmt->execute();
        $chkStmt->store_result();
        $chkStmt->bind_result($tempMail);
        $chkStmt->fetch();
        
        if ($chkStmt->num_rows != 1)
        {
            $tmpPass = rand(10000, 30000);
            $tmpPass2 = md5($tmpPass);
            if ($inStmt = $dbConnection->prepare("INSERT INTO users (first, last, email, gender, country, year, salt, password, lotter, active, tmp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
            {
                $inStmt->bind_param("sssisissiii", $_POST["first"], $_POST["last"], $_POST["email"], $_POST["gender"], $_POST["country"], $_POST["year"], $rndSalt, $password, 0, 0, $tmpPass2);
                $inStmt->execute();
                echo "signing up";
                $msg = "Thank you ".$_POST["first"]." ".$_POST["last"]." for signing up to use GameQ!/r/n The first time you log in please use this password to verify your e-mail address:/r/n /r/n" . $tmpPass;
                $msg = wordwrap($msg, 70, "/r/n");
                $to = $_POST["email"];
                $subject = "GameQ || E-mail Verification";
                mail($to, $subject, $msg);
            }
            else
            {
                echo "no";
            }

        }
        else
            echo "duplicate";
    }
    else
        echo "no";
    

?>