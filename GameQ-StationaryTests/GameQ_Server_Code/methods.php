<?php

    function secureSessionStart()
    {
        $sessionName = "secureSession";
        $isSecure = true;
        $httpOnly = true;
        
        ini_set("session.use_only_cookies", 1);
        $cookieParams = session_get_cookie_params();
        session_set_cookie_params($cookieParams["lifetime"], $cookieParams["path"], $cookieParams["domain"], $isSecure, $httpOnly);
        session_name($sessionName);
        session_start();
        session_regenerate_id(true);
    }
    
    function login($email, $password, $dbConnection)
    {
        if($stmt = $dbConnection->prepare("SELECT id, password, salt, active, tmp FROM users WHERE email = ? LIMIT 1"))
        {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($userID, $chkPassword, $salt, $active, $tmpPass);
            $stmt->fetch();
            
            
            
            if($stmt->num_rows == 1)
            {
                if(bruteForce($userID, $dbConnection) == true)
                {
                    //let user know they're locked
                    return false;
                }
                else
                {
                    if ($active == 1)
                    {
                        $password = hash("sha512", $password.$salt);
                        if($chkPassword = $password)
                        {
                            $userBrowsingAgent = $_SERVER["HTTP_USER_AGENT"];
                            $userID = preg_replace("/[^0-9]+/", "", $userID);
                            $_SESSION["userID"] = $userID;
                            $_SESSION["loginStr"] = hash("sha512", $password.$userBrowsingAgent);
                            
                            //login success
                            return true;
                            
                        }
                        else
                        {
                            //login denied
                            $time = time();
                            if ($insStmt = $dbConnection->prepare("INSERT INTO loginAttempts (userID, time) VALUES (?, ?)"))
                            {
                                $insStmt->bind_param("ii" ,$userID, $time);
                            }
                            return false;
                        }
                    }
                    if ($active == 0)
                    {
                        if($tmpPass == $password)
                        {
                            $password = $chkPassword;
                            $userBrowsingAgent = $_SERVER["HTTP_USER_AGENT"];
                            $userID = preg_replace("/[^0-9]+/", "", $userID);
                            $_SESSION["userID"] = $userID;
                            $_SESSION["loginStr"] = hash("sha512", $password.$userBrowsingAgent);
                            
                            //login success
                            $active = 1;
                            $updStmt = $dbConnection->prepare("UPDATE users SET active = ? WHERE id = ? LIMIT 1");
                            $updStmt->bind_param("ii", $active, $userID);
                            $updStmt->execute();
                            return true;
                            
                        }
                        else
                        {
                            //login denied
                            $time = time();
                            if ($insStmt = $dbConnection->prepare("INSERT INTO loginAttempts (userID, time) VALUES (?, ?)"))
                            {
                                $insStmt->bind_param("ii" ,$userID, $time);
                            }
                            return false;
                        }
                    }
                }
            }
            else
            {
                return false;
            }
            
        }
    }
    
    function bruteForce($userID, $dbConnection)
    {
        $time = time();
        $recentAttempts = $time - 7200;
        
        if ($stmt = $dbConnection->prepare("SELECT time FROM loginAttempts WHERE userID = ? AND time > ?"))
        {
            $stmt->bind_param("ii", $userID, $time);
            $stmt->execute();
            $stmt->store_result();
            if($stmt->num_rows > 6);
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        
    }
    
    function chkLogin($dbConnection)
    {
        if (isset($_SESSION["userID"], $_SESSION["loginStr"]))
        {
            $userID = $_SESSION["userID"];
            $loginStr = $_SESSION["loginStr"];
            $userBrowsingAgent = $_SERVER[HTTP_USER_AGENT];
            
            if ( $stmt = $dbConnection->prepare("SELECT password FROM users WHERE id = ? LIMIT 1"))
            {
                $stmt->bind_param("i", $userID);
                $stmt->execute();
                $stmt->store_result();
                
                if($stmt->num_rows == 1)
                {
                    $stmt->bind_result($chkPassword);
                    $stmt->fetch();
                    $loginChk = hash("sha512", $chkPassword.$userBrowsingAgent);
                    if ($loginChk == $loginStr)
                    {
                        return true;
                    }
                    else
                        return false;
                }
                else
                    return false;
            }
            else
                return false;
        }
        else
            return false;
    }
    function pushGame($game)
    {
        // Using Autoload all classes are loaded on-demand
        require_once 'ApnsPHP/Autoload.php';
        
        // Instanciate a new ApnsPHP_Push object
        $push = new ApnsPHP_Push(
                                 ApnsPHP_Abstract::ENVIRONMENT_SANDBOX,
                                 'server_certificates_bundle_sandbox.pem'
                                 );
        
        // Set the Provider Certificate passphrase
        // $push->setProviderCertificatePassphrase('test');
        
        // Set the Root Certificate Authority to verify the Apple remote peer
        $push->setRootCertificationAuthority('entrust_root_certification_authority.pem');
        
        // Connect to the Apple Push Notification Service
        $push->connect();
        
        // Instantiate a new Message with a single recipient
        $message = new ApnsPHP_Message($_SESSION["token"]);
        
        // Set a simple welcome text
        $message->setText('Hello APNs-enabled device!');
        
        // Play the default sound
        $message->setSound();
        
        // Set a custom property
        //$message->setCustomProperty('acme2', array('bang', 'whiz'));
        
        // Set another custom property
        //$message->setCustomProperty('acme3', array('bing', 'bong'));
        
        // Set the expiry value to 60 seconds
        $message->setExpiry(60);
        
        // Add the message to the message queue
        $push->add($message);
        
        // Send all messages in the message queue
        $push->send();
    }

    

    
    
    
    
    
?>