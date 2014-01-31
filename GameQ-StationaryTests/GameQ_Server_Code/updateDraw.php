<?php
    include "connect.php";
    include "methods.php";
    if (chkLogin($dbConnection))
    {
        if ($upStmt = $dbConnection->prepare("SELECT time FROM computers WHERE id = ?"))
        {
            
            $upStmt->bind_param("s", $_SESSION["userID"]);
            $upStmt->execute();
            $upStmt->store_result();
            $upStmt->bind_result($lotter);
            $upStmt->fetch();
            if ($upStmt->num_rows > 0)
            {
                while($tmpData = mysql_fetch_array($upStmt)) {
                    
                    if ($tmpData[column_time] > 604800) //one week
                    {
                        if ($inStmt = $dbConnection->prepare("DELETE FROM computers WHERE time = ?"))
                        {
                            $inStmt->bind_param("i", $tmpData[column_time]);
                            $inStmt->execute();
                        }
                    }
                }
            }
            
            
        }

        if ($inStmt = $dbConnection->prepare("DELETE FROM computers WHERE time = ?"))
        {
            $inStmt->bind_param("s", $_SESSION["token"]);
            $inStmt->execute();
        }
        
        if ($upStmt = $dbConnection->prepare("SELECT name, game, status FROM computers WHERE id = ?"))
        {
            $upStmt->bind_param("s", $_SESSION["userID"]);
            $upStmt->execute();
            $upStmt->store_result();
            $upStmt->bind_result($lotter);
            $upStmt->fetch();
            
            if ($upStmt->num_rows > 0)
            {
                $returnString = "";
                $returnInt = 0;
                $tempString = "";
                while($tmpData = mysql_fetch_array($upStmt)) {
                    
                    $tmpString = $tmpData["column_game"] . $tmpData["column_status"] . $tmpData["column_name"];
                    $returnInt += 1;
                    $lenInt = strlen($tmpData["column_name"]);
                    if ($lenInt >= 10) {
                        $tempString = $lenInt . $tmpString;
                    } else {
                        $tempString = "0" . $lenInt . $tmpString;
                    }
                }
                
                if (returnInt >= 10) {
                    $returnString = "updating" . $returnInt . $tempString;
                } else {
                    $returnString = "updating" . "0" . $returnInt . $tempString;
                }
                echo $returnString;
            }
            else
                echo "updating00";
            
            
        }
        else
            echo "no";
    }
    else
    {
        echo "badsession";
    }
    
    
?>