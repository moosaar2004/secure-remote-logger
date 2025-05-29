//AUTHOR: Ali Rehman; NetID: amr567

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class LogServer {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(0);
            int port = serverSocket.getLocalPort();
            System.out.println("LogServer listening on port: " + port);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected.");
                handleClient(clientSocket);
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        ) {
            String message = in.readLine();
            if (message == null) {
                out.println("error: empty message");
                return;
            }
            System.out.println("Received: " + message);

            // Validate proof-of-work
            if (!validateProofOfWork(message)) {
                out.println("error: invalid proof of work");
                return;
            }

            // Strip proof-of-work
            int colonIndex = message.indexOf(": ");
            if (colonIndex == -1) {
                out.println("error: malformed message");
                return;
            }
            String logText = message.substring(colonIndex + 2);

            // Read previous hash from loghead.txt
            String prevHash = "start";
            File logFile = new File("log.txt");
            File headFile = new File("loghead.txt");
            if (logFile.exists()) {
                if (!headFile.exists()) {
                    out.println("error: head pointer file missing");
                    return;
                }
                try (BufferedReader headReader = new BufferedReader(new FileReader(headFile))) {
                    prevHash = headReader.readLine();
                    if (prevHash == null) prevHash = "start";
                }
            }

            // Create log entry
            String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            String logEntry = timestamp + " - " + prevHash + " " + logText;

            // Compute new hash
            String newHash = computeHash(logEntry);

            // Append to log.txt
            try (BufferedWriter logWriter = new BufferedWriter(new FileWriter("log.txt", true))) {
                logWriter.write(logEntry);
                logWriter.newLine();
            }

            // Update loghead.txt
            try (BufferedWriter headWriter = new BufferedWriter(new FileWriter("loghead.txt"))) {
                headWriter.write(newHash);
            }

            out.println("ok");
            System.out.println("sending response: ok");
        } catch (IOException e) {
            System.err.println("Client handling error: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }

    private static boolean validateProofOfWork(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            return hasLeadingZeros(hash, 22);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-256 not available: " + e.getMessage());
            return false;
        }
    }

    private static boolean hasLeadingZeros(byte[] hash, int requiredZeros) {
        int zeroBits = 0;
        for (byte b : hash) {
            if (b == 0) {
                zeroBits += 8;
            } else {
                zeroBits += Integer.numberOfLeadingZeros(b & 0xFF) - 24;
                break;
            }
            if (zeroBits >= requiredZeros) return true;
        }
        return zeroBits >= requiredZeros;
    }

    private static String computeHash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            String base64Hash = Base64.getEncoder().encodeToString(hash);
            return base64Hash.substring(base64Hash.length() - 24);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-256 not available: " + e.getMessage());
            return "";
        }
    }
}