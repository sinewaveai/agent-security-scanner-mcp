// Benchmark corpus: Java security vulnerabilities
package com.example.security;

import java.sql.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.xml.parsers.*;
import org.xml.sax.*;

public class SecurityBenchmark {

    // --- SQL Injection ---

    public void unsafeJdbcQuery(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        // VULN: sql-injection-jdbc
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    public void unsafeJdbcQuery2(Connection conn, String name) throws SQLException {
        // VULN: sql-injection-jdbc
        conn.createStatement().executeUpdate("INSERT INTO users (name) VALUES ('" + name + "')");
    }

    public void safeJdbcQuery(Connection conn, String userId) throws SQLException {
        // SAFE: sql-injection-jdbc
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, userId);
        pstmt.executeQuery();
    }

    // --- Command Injection ---

    public void unsafeRuntimeExec(String userInput) throws IOException {
        // VULN: command-injection-runtime-exec
        Runtime.getRuntime().exec("cat " + userInput);
    }

    public void unsafeProcessBuilder(String userInput) throws IOException {
        // VULN: command-injection-process-builder
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "echo " + userInput);
        pb.start();
    }

    public void safeRuntimeExec() throws IOException {
        // SAFE: command-injection-runtime-exec
        Runtime.getRuntime().exec(new String[]{"cat", "/etc/passwd"});
    }

    // --- XXE ---

    public void unsafeXXE(InputStream xmlInput) throws Exception {
        // VULN: xxe-saxparser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(xmlInput, new DefaultHandler());
    }

    public void safeXXE(InputStream xmlInput) throws Exception {
        // SAFE: xxe-saxparser
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        SAXParser parser = factory.newSAXParser();
        parser.parse(xmlInput, new DefaultHandler());
    }

    // --- Deserialization ---

    public Object unsafeDeserialize(InputStream input) throws Exception {
        // VULN: object-inputstream
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }

    public void safeJsonParse(String json) {
        // SAFE: object-inputstream
        // Use JSON parser instead of ObjectInputStream
    }

    // --- Weak Cryptography ---

    public byte[] weakMD5(byte[] data) throws NoSuchAlgorithmException {
        // VULN: weak-hash-md5
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    public byte[] weakSHA1(byte[] data) throws NoSuchAlgorithmException {
        // VULN: weak-hash-sha1
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    public Cipher weakDES() throws Exception {
        // VULN: weak-cipher-des
        return Cipher.getInstance("DES");
    }

    public Cipher weakECB() throws Exception {
        // VULN: ecb-mode
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public byte[] strongHash(byte[] data) throws NoSuchAlgorithmException {
        // SAFE: weak-hash-md5
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    public Cipher strongCipher() throws Exception {
        // SAFE: weak-cipher-des
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    // --- Insecure Random ---

    public int weakRandom() {
        // VULN: insecure-random
        java.util.Random rand = new java.util.Random();
        return rand.nextInt();
    }

    public int secureRandom() throws NoSuchAlgorithmException {
        // SAFE: insecure-random
        SecureRandom rand = SecureRandom.getInstanceStrong();
        return rand.nextInt();
    }

    // --- Path Traversal ---

    public void unsafeFileRead(String userPath) throws IOException {
        // VULN: path-traversal-file
        File file = new File("/uploads/" + userPath);
        FileInputStream fis = new FileInputStream(file);
    }

    public void safeFileRead(String filename) throws IOException {
        // SAFE: path-traversal-file
        File file = new File("/uploads", filename);
        if (!file.getCanonicalPath().startsWith("/uploads/")) {
            throw new SecurityException("Path traversal detected");
        }
    }

    // --- SSRF ---

    public void unsafeSSRF(String userUrl) throws Exception {
        // VULN: ssrf-url
        URL url = new URL("http://internal/" + userUrl);
        url.openConnection();
    }

    public void safeURL() throws Exception {
        // SAFE: ssrf-url
        URL url = new URL("https://api.example.com/data");
        url.openConnection();
    }

    // --- Hardcoded Credentials ---

    // VULN: hardcoded-password
    private String password = "SuperSecret123!";

    // VULN: hardcoded-secret-key
    private String secretKey = "AKIAIOSFODNN7EXAMPLE";

    // SAFE: hardcoded-password
    private String passwordEnv = System.getenv("DB_PASSWORD");

    // --- LDAP Injection ---

    public void unsafeLDAP(String userInput) {
        // VULN: ldap-injection
        String filter = "(uid=" + userInput + ")";
    }

    // --- XPath Injection ---

    public void unsafeXPath(String userInput) {
        // VULN: xpath-injection
        String xpath = "//users/user[@name='" + userInput + "']";
    }
}
