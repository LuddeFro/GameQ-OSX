<?php
   include "methods.php";
    if (chkLogin($dbConnection)) {
        if ($_SESSION["device"] == "mac") {
            
            if ($updStmt = $dbConnection->prepare("UPDATE computers SET time = ?, game = ? WHERE token = ? LIMIT 1");)
            {
                $time = time();
                $inStmt->bind_param("iis", $time, 04, $_SESSION["token"]);
                $inStmt->execute();
            }
            
        } else if ($_SESSION["device"] == "iphone") {
            if ($inStmt = $dbConnection->prepare("DELETE FROM devices WHERE token = ?"))
            {
                $inStmt->bind_param("s", $_SESSION["token"]);
                $inStmt->execute();
            }
        }
        
        
    }
    
    secureSessionStart();
    
    $_SESSION = array();
    $params = session_get_cookie_params();
    setcookie(session_name(), "", time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    session_destroy();
    header("Location: ./");
    echo "logged out";
?>