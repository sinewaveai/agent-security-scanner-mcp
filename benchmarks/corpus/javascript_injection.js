/**
 * Benchmark corpus: JavaScript injection vulnerabilities (eval, command injection, SQL injection).
 */
var userInput = "alert(1)";

// --- eval / code injection ---

// VULN: eval-detected
eval(userInput);

// VULN: function-constructor
var fn = new Function(userInput);

// VULN: setTimeout-string
setTimeout("alert('xss')", 1000);

// SAFE: eval-detected
JSON.parse(userInput);

// SAFE: setTimeout-string
setTimeout(handleTimeout, 1000);

// --- Command injection ---

var child_process = require("child_process");
var filename = "user_provided.txt";

// VULN: child-process-exec
child_process.exec("cat " + filename);

// VULN: spawn-shell
child_process.spawn("bash", ["-c", "cat " + filename], { shell: true });

// SAFE: child-process-exec
child_process.execFile("cat", [filename]);

// SAFE: spawn-shell
child_process.spawn("cat", [filename], { shell: false });

// --- SQL injection ---

var userId = "1 OR 1=1";

// VULN: sql-injection
db.query("SELECT * FROM users WHERE id = " + userId);

// SAFE: sql-injection
db.query("SELECT * FROM users WHERE id = ?", [userId]);

// --- Crypto ---

var crypto = require("crypto");

// VULN: insecure-hash-md5
var hash = crypto.createHash("md5").update(data).digest("hex");

// VULN: insecure-hash-sha1
var hash = crypto.createHash("sha1").update(data).digest("hex");

// SAFE: insecure-hash-md5
var hash = crypto.createHash("sha256").update(data).digest("hex");

// VULN: insecure-random
var token = Math.random().toString(36);

// SAFE: insecure-random
var token = crypto.randomBytes(32).toString("hex");
