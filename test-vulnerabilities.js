// Test file for Agent Security Analyzer Extension
// This file contains intentional security vulnerabilities for testing

// ❌ SQL Injection - should be detected
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId; // vulnerable line rtrt
db.execute(query);

// ❌ XSS (Cross-Site Scripting) - should be detected ....
const userComment = req.body.comment;
document.getElementById('display').innerHTML = userComment;

// ❌ Path Traversal - should be detected
const filename = req.query.file;
const content = fs.readFileSync('./uploads/' + filename);

// ❌ Command Injection - should be detected
const userInput = req.body.command;
exec('ls ' + userInput, (error, stdout) => {
    console.log(stdout);
});

// ❌ Hardcoded Secrets - should be detected
const API_KEY = "stripe_test_FAKEFAKEFAKEFAKEFAKE1234";
const password = "MySecretPassword123!";
const privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B";

// ✅ Safe practices (should NOT be detected)
const safeQuery = "SELECT * FROM users WHERE id = ?";
db.execute(safeQuery, [userId]);

const safeElement = document.createTextNode(userComment);
document.getElementById('display').appendChild(safeElement);

const safeFilePath = path.join(__dirname, 'uploads', path.basename(filename));
const safeContent = fs.readFileSync(safeFilePath);

const apiKey = process.env.API_KEY;
const pwd = process.env.DATABASE_PASSWORD;
