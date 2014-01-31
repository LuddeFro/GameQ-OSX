<?php
    include "connect.php";
    include "methods.php";
    if (chkLogin($dbConnection))
    {
        
        if(isset($_POST["token"], $_POST["device"])) {
            
            if($stmt = $dbConnection->prepare("SELECT token, deviceID FROM devices WHERE id = ? AND token = ? LIMIT 1"))
            {
                $stmt->bind_param("is", $_SESSION["userID"], $_POST["token"]);
                $stmt->execute();
                $stmt->store_result();
                $stmt->bind_result($doubleToken, $deviceID);
                $stmt->fetch();
                
                if($stmt->num_rows == 1) {
                    
                    echo "postedDevice";
                    $_SESSION["device"] = "iphone";
                    $_SESSION["token"] = $_POST["token"];
                } else {
                    
                    if ($inStmt = $dbConnection->prepare("INSERT INTO devices (name, token, id) VALUES (?, ?, ?)")) {
                        
                        $stmt->bind_param("ssi", $_POST["device"], $_POST["token"], $_SESSION["userID"]);
                        $stmt->execute();
                        echo "postedDevice";
                        $_SESSION["device"] = "iphone";
                        $_SESSION["token"] = $_POST["token"];
                        
                    } else { echo "no" }
                    
                }
                
            } else { echo "no" }
            
            
        } else { echo "no" }
        
    }
    else
        echo "badsession";
?>