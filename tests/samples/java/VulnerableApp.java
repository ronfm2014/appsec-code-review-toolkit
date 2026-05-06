/**
 * Intentionally Vulnerable Java Application — Scanner Test Target
 * Contains deliberate vulnerabilities to validate scanner detection.
 * DO NOT DEPLOY. FOR TESTING ONLY.
 */

import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.xml.parsers.*;
import java.nio.file.*;
import java.net.*;

public class VulnerableApp {

    // ── Hardcoded Secrets (JAVA-A02-001) ─────────────────────────────────
    private static final String DB_PASSWORD = "SuperSecret123!";   // VULN
    private static final String API_KEY     = "sk-prod-abc123";    // VULN
    private String token = "hardcoded-jwt-secret";                  // VULN

    // ── SQL Injection (JAVA-A03-001) ──────────────────────────────────────
    public ResultSet getUserById(Connection conn, String userId) throws SQLException {
        // VULN: string concatenation in executeQuery
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    public void updateEmail(Connection conn, String userId, String email)
            throws SQLException {
        // VULN: string concatenation in prepareStatement
        PreparedStatement ps = conn.prepareStatement(
            "UPDATE users SET email = '" + email + "' WHERE id = " + userId);
        ps.executeUpdate();
    }

    // ── Weak Crypto (JAVA-A02-002) ────────────────────────────────────────
    public String hashPasswordInsecure(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");     // VULN: MD5
        byte[] hash = md.digest(password.getBytes());
        return bytesToHex(hash);
    }

    public String signatureInsecure(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");   // VULN: SHA-1
        return bytesToHex(md.digest(data.getBytes()));
    }

    // ── XXE Injection (JAVA-A05-001) ─────────────────────────────────────
    public void parseXmlInsecure(InputStream xmlInput) throws Exception {
        // VULN: DocumentBuilderFactory without XXE mitigations
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xmlInput);
    }

    public void parseSaxInsecure(InputStream xmlInput) throws Exception {
        // VULN: SAXParserFactory without XXE mitigations
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
    }

    // ── Path Traversal (JAVA-A01-001) ─────────────────────────────────────
    public String readUserFile(String filename) throws IOException {
        // VULN: File constructed with user input via concatenation
        File file = new File("/app/uploads/" + filename);
        return new String(Files.readAllBytes(file.toPath()));
    }

    public byte[] downloadReport(String reportName) throws IOException {
        // VULN: Paths.get with concatenation — no canonicalization
        Path path = Paths.get("/app/reports/" + reportName);
        return Files.readAllBytes(path);
    }

    // ── Helper ─────────────────────────────────────────────────────────────
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
