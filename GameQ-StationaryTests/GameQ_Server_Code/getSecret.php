<?php
    include "connect.php";
    
    if (isset($_POST["email"]))
    {
        if ($secStmt = $dbConnection->prepare("SELECT secretQ FROM users WHERE email = ? LIMIT 1"))
        {
            $secStmt->bind_param("s", $_POST["email"]);
            $secStmt->execute();
            $secStmt->store_result();
            $secStmt->bind_result($secretQ);
            $secStmt->fetch();
            
            if ($secStmt->num_rows == 1)
            {
                echo "secQ" . $secretQ;
            }
            else
                echo "wronguser";
        }
        else
            echo "no";
    }
    else
        echo "no";
?>