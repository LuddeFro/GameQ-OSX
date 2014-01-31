<?php
    include "connect.php";
    include "methods.php";
    if (chkLogin($dbConnection))
    {
        $game = "";
        
        if(isset($_POST["game"])) {
            if (strlen($_POST["game"] < 2)) {
                $game = "0" . $_POST["game"];
            } else {
                $game = $_POST["game"];
            }
            $status = "02";
            
            if ($_SESSION["device"] = "mac") {
                if ($inStmt = $dbConnection->prepare("UPDATE computers SET game = ?, staus = ? WHERE token = ? LIMIT 1"))
                {
                    $inStmt->bind_param("sss", $game, $status, $_SESSION["token"]);
                    $inStmt->execute();
                    
                    
                    //push it
                    
                    
                    pushGame($game);
                    
                    
                    
                    
                }

            } else if ($_SESSION["device"] = "pc") {
                //todo
            } else { echo "no" }
            
            
        } else { echo "no" }
        
    }
    else
        echo "badsession";
?>