<?php
/**
 * Vulnerable PHP Sample for Testing Security Scanner
 * This file contains intentional security vulnerabilities for testing purposes
 * DO NOT use this code in production!
 */

// Database configuration
$host = 'localhost';
$dbname = 'test_db';
$username = 'root';
$password = '';

// Connect to MySQL
$connection = mysql_connect($host, $username, $password);
mysql_select_db($dbname, $connection);

// VULNERABILITY 1: SQL Injection - User input directly in query
function getUser($userId) {
    global $connection;
    $query = "SELECT * FROM users WHERE id = " . $_GET['user_id'];
    $result = mysql_query($query, $connection);
    return mysql_fetch_assoc($result);
}

// VULNERABILITY 2: SQL Injection - Dynamic query construction
function searchUsers($searchTerm) {
    global $connection;
    $query = "SELECT * FROM users WHERE name LIKE '%" . $_POST['search'] . "%'";
    $result = mysql_query($query, $connection);
    return $result;
}

// VULNERABILITY 3: XSS - Direct output of user input
function displayComment() {
    echo "User comment: " . $_GET['comment'];
}

// VULNERABILITY 4: XSS - Unescaped output in HTML
function showUserProfile() {
    $username = $_POST['username'];
    echo "<h1>Welcome $username!</h1>";
}

// VULNERABILITY 5: Missing Input Validation
function processRegistration() {
    $email = $_POST['email'];  // No validation
    $password = $_POST['password'];  // No validation
    
    // Direct insertion without validation
    $query = "INSERT INTO users (email, password) VALUES ('$email', '$password')";
    mysql_query($query, $connection);
}

// VULNERABILITY 6: File inclusion vulnerability
function includePage() {
    $page = $_GET['page'];
    include($page . '.php');  // Dangerous file inclusion
}

// VULNERABILITY 7: eval() usage - Remote code execution
function calculateExpression() {
    $expression = $_GET['calc'];
    $result = eval("return $expression;");  // Extremely dangerous
    return $result;
}

// VULNERABILITY 8: Command injection
function pingServer() {
    $host = $_POST['host'];
    $output = shell_exec("ping -c 4 " . $host);  // Command injection
    echo "<pre>$output</pre>";
}

// VULNERABILITY 9: Unserialize usage - Object injection
function loadUserData() {
    $userData = $_POST['data'];
    $object = unserialize($userData);  // Dangerous unserialize
    return $object;
}

// VULNERABILITY 10: Missing output encoding
function displaySearchResults() {
    $query = $_GET['q'];
    echo "Search results for: " . $query;  // XSS vulnerability
    
    // Another XSS example
    foreach ($_GET as $key => $value) {
        echo "$key: $value<br>";  // Direct output
    }
}

// VULNERABILITY 11: SQL Injection with PDO (wrong usage)
function getUserBadPDO($userId) {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $sql = "SELECT * FROM users WHERE id = " . $_GET['id'];  // Still vulnerable
    $stmt = $pdo->query($sql);
    return $stmt->fetch();
}

// VULNERABILITY 12: Missing CSRF protection
function changePassword() {
    $newPassword = $_POST['new_password'];
    $userId = $_POST['user_id'];
    
    // No CSRF token check
    $query = "UPDATE users SET password = '$newPassword' WHERE id = $userId";
    mysql_query($query, $connection);
}

// VULNERABILITY 13: Path traversal
function readFileContent() {
    $filename = $_GET['file'];
    $content = file_get_contents('/var/www/uploads/' . $filename);  // Path traversal
    echo $content;
}

// VULNERABILITY 14: Weak password handling
function authenticateUser() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = mysql_query($query, $connection);
    
    if (mysql_num_rows($result) > 0) {
        $_SESSION['logged_in'] = true;
        return true;
    }
    return false;
}

// VULNERABILITY 15: Information disclosure
function showError() {
    $error = mysql_error($connection);
    echo "Database error: " . $error;  // Information disclosure
}

// Main execution
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Process various GET requests with vulnerabilities
    if (isset($_GET['action'])) {
        switch ($_GET['action']) {
            case 'profile':
                showUserProfile();
                break;
            case 'comment':
                displayComment();
                break;
            case 'search':
                displaySearchResults();
                break;
            case 'calculate':
                calculateExpression();
                break;
            case 'include':
                includePage();
                break;
            case 'read':
                readFileContent();
                break;
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Process various POST requests with vulnerabilities
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'register':
                processRegistration();
                break;
            case 'search_users':
                searchUsers($_POST['search']);
                break;
            case 'ping':
                pingServer();
                break;
            case 'load_data':
                loadUserData();
                break;
            case 'change_password':
                changePassword();
                break;
            case 'login':
                authenticateUser();
                break;
        }
    }
}

// Some additional vulnerable code for comprehensive testing

// VULNERABILITY 16: XSS with direct output
$userInput = $_GET['input'];
echo $userInput;

// VULNERABILITY 17: SQL injection in UPDATE
function updateUserEmail() {
    $newEmail = $_GET['email'];
    $userId = $_GET['id'];
    $query = "UPDATE users SET email = '$newEmail' WHERE id = $userId";
    mysql_query($query, $connection);
}

// VULNERABILITY 18: Multiple SQL injections in one function
function complexQuery() {
    $name = $_GET['name'];
    $age = $_GET['age'];
    $city = $_GET['city'];
    
    $query = "SELECT * FROM users WHERE name LIKE '%$name%' AND age > $age AND city = '$city'";
    $result = mysql_query($query, $connection);
    
    while ($row = mysql_fetch_assoc($result)) {
        echo "User: " . $row['name'] . "<br>";  // XSS in output
    }
}

?>
