<?php
    include "connect.php";
    include "methods.php";
    if (chkLogin($dbConnection))
    {
        
        if(isset($_POST["game"], $_POST["status"])) {
            if (strlen($_POST["game"] < 2)) {
                $game = "0" . $_POST["game"];
            } else {
                $game = $_POST["game"];
            }
            if (strlen($_POST["status"] < 2)) {
                $status = "0" . $_POST["status"];
            } else {
                $status = $_POST["status"];
            }
            
            if ($_SESSION["device"] = "mac") {
                if ($inStmt = $dbConnection->prepare("UPDATE computers SET game = ?, staus = ? WHERE token = ? LIMIT 1"))
                {
                    $inStmt->bind_param("sss", $game, $status, $_SESSION["token"]);
                    $inStmt->execute();
                }
                
                
                // push it
                
                
                

            } else if ($_SESSION["device"] = "pc") {
                //todo
            } else { echo "no" }
            
            
        } else { echo "no" }
        
    }
    else
        echo "badsession";
?>