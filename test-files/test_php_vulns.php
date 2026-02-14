<?php
// Test file for PHP security rules
// Contains intentional vulnerabilities for testing

// SQL Injection - should be detected
$user_id = $_GET['id'];
$result = $db->query("SELECT * FROM users WHERE id = " . $_GET['id']);
$sql = sprintf("SELECT * FROM products WHERE name = '%s'", $user_input);

// Command Injection - should be detected
system("ls " . $_GET['dir']);
exec("ping " . $_POST['host']);
$output = `cat $_REQUEST['file']`;

// Code Injection - should be detected
eval($_POST['code']);
assert($_GET['expr']);
preg_replace('/test/e', $_GET['replacement'], $input);

// File Inclusion - should be detected
include($_GET['page']);
require_once($_POST['module']);

// XSS - should be detected
echo $_GET['name'];
print $_POST['message'];
<?= $_REQUEST['data'] ?>

// Deserialization - should be detected
$obj = unserialize($_COOKIE['session']);

// Weak Crypto - should be detected
$hash = md5($password);
$hash2 = sha1($secret);
mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);

// Weak Random - should be detected
$token = rand();
$id = mt_rand(1, 1000);

// SSL Disabled - should be detected
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

// SSRF - should be detected
$content = file_get_contents($_GET['url']);

// Path Traversal - should be detected
$data = file_get_contents("../config/" . $_GET['file']);
readfile($_POST['path']);

// Open Redirect - should be detected
header("Location: " . $_GET['redirect']);

// Hardcoded Credentials - should be detected
$password = "supersecretpassword123";
$api_key = "test_FAKEFAKEFAKEFAKE1234";

// Information Disclosure - should be detected
phpinfo();
ini_set('display_errors', '1');

// CORS - should be detected
header("Access-Control-Allow-Origin: *");

echo "Test file for PHP vulnerabilities";
?>
