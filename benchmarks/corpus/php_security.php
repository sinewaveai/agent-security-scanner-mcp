<?php
// Benchmark corpus: PHP security vulnerabilities

// --- SQL Injection ---

// VULN: sql-injection-query
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// VULN: sql-injection-sprintf
$query = sprintf("SELECT * FROM users WHERE name = '%s'", $_POST['name']);

// SAFE: sql-injection-query
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();

// --- Command Injection ---

// VULN: command-injection-exec
exec("cat " . $_GET['file']);

// VULN: command-injection-exec
system("ls " . $userInput);

// VULN: command-injection-exec
passthru("grep " . $pattern);

// VULN: backticks-exec
$output = `cat $filename`;

// SAFE: command-injection-exec
exec(escapeshellcmd("cat " . escapeshellarg($file)));

// --- Code Injection ---

// VULN: eval-usage
eval($_GET['code']);

// VULN: assert-usage
assert($_POST['expression']);

// VULN: preg-code-exec
preg_replace('/e', $_GET['replacement'], $subject);

// SAFE: eval-usage
$result = json_decode($jsonString, true);

// --- File Inclusion ---

// VULN: file-inclusion
include($_GET['page'] . ".php");

// VULN: file-inclusion
require($userInput);

// SAFE: file-inclusion
$allowed = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $allowed)) {
    include($_GET['page'] . ".php");
}

// --- XSS ---

// VULN: xss-echo
echo $_GET['name'];

// VULN: xss-echo
print $_POST['message'];

// SAFE: xss-echo
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// --- Deserialization ---

// VULN: unsafe-unserialize
$data = unserialize($_POST['data']);

// SAFE: unsafe-unserialize
$data = json_decode($_POST['data'], true);

// --- Weak Cryptography ---

// VULN: weak-hash-md5
$hash = md5($password);

// VULN: weak-hash-sha1
$hash = sha1($password);

// VULN: weak-random
$token = rand();

// SAFE: weak-hash-md5
$hash = password_hash($password, PASSWORD_BCRYPT);

// SAFE: weak-random
$token = random_bytes(32);

// --- SSL/TLS ---

// VULN: curl-ssl-disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

// VULN: curl-ssl-disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

// SAFE: curl-ssl-disabled
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

// --- SSRF ---

// VULN: ssrf
file_get_contents($_GET['url']);

// VULN: ssrf
$ch = curl_init($_POST['url']);

// SAFE: ssrf
file_get_contents("https://api.example.com/data");

// --- Path Traversal ---

// VULN: path-traversal
readfile("/uploads/" . $_GET['file']);

// VULN: path-traversal
file_get_contents("../../../etc/passwd");

// SAFE: path-traversal
$filename = basename($_GET['file']);
readfile("/uploads/" . $filename);

// --- Open Redirect ---

// VULN: open-redirect
header("Location: " . $_GET['redirect']);

// SAFE: open-redirect
$allowed_urls = ['https://example.com'];
if (in_array($_GET['redirect'], $allowed_urls)) {
    header("Location: " . $_GET['redirect']);
}

// --- LDAP Injection ---

// VULN: ldap-injection
$filter = "(uid=" . $_GET['username'] . ")";

// --- XXE ---

// VULN: xxe
$xml = simplexml_load_string($xmlData);

// SAFE: xxe
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($xmlData);

// --- Hardcoded Credentials ---

// VULN: hardcoded-password
$password = "SuperSecret123!";

// VULN: hardcoded-api-key
$api_key = "test_FAKEFAKEFAKE1234";

// SAFE: hardcoded-password
$password = getenv("DB_PASSWORD");

// --- Information Exposure ---

// VULN: phpinfo-exposure
phpinfo();

// VULN: error-display
ini_set('display_errors', 1);

// --- CORS ---

// VULN: permissive-cors
header("Access-Control-Allow-Origin: *");

// SAFE: permissive-cors
header("Access-Control-Allow-Origin: https://trusted.example.com");

?>
