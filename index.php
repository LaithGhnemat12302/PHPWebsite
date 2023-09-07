<?php
session_start();
include ('db.php');
$pdo=db_connect();

if(isset($_POST["Register"])){
    try {
    
    if (strlen($_POST["password"]) < 8) {
        die("Password must be at least 8 characters");
    }
    
    if ($_POST["password"] !== $_POST["confirm"]) {
        echo "The Password Does Not Match!";
    }
    
    $username=$_POST["username"];
    $email=$_POST["email"];
    $password=$_POST["password"];
    $confirm=$_POST["confirm"];
    
    
    $sql = "INSERT INTO user_registration (username, email, password) VALUES (:username, :email, :password)";
    $stmt = $pdo->prepare($sql);
    
        if (!$stmt) {
            die("SQL error: " . $pdo->errorInfo()[2]);
        }
       
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':username', $username);
    
        if ($stmt->execute()) {
            $_SESSION['email'] = $email;
            header("Location: dashboard.php");
        } else {
            $errorCode = $stmt->errorInfo()[1];
            if ($errorCode === 1062) {
                die("Email already taken");
            } else {
                die("Database error: " . $stmt->errorInfo()[2]);
            }
        }
    } catch (PDOException $e) {
        die("Database connection failed: " . $e->getMessage());
    }
}
else if(isset($_POST["LogIn"])){
    $emailSignUp=$_POST["emailSignUp"];
    $passwordSignUp=$_POST["passwordSignUp"];

    $usernameSignUp="SELECT username FROM user_registration where email=:emailSignUp";


$sql = "SELECT * FROM user_registration WHERE email = :emailSignUp AND password = :passwordSignUp";
$stmt = $pdo->prepare($sql);
$stmt->bindParam(':emailSignUp', $emailSignUp);
$stmt->bindParam(':passwordSignUp', $passwordSignUp);
$stmt->execute();


$username=$pdo->prepare($usernameSignUp);
$username->bindParam(':emailSignUp',$emailSignUp);
$username->execute();
$usernameExists = $username->fetch(PDO::FETCH_ASSOC);


if ($stmt->rowCount() > 0) {
    $_SESSION['username'] = $usernameExists['username'];
    $_SESSION['emailSignUp'] = $emailSignUp;
    header("Location: dashboard.php");
} else {

    echo "Invalid email or password.";
}
    
}

?>