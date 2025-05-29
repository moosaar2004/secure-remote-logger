//AUTHOR: Ali Rehman; NetID: amr567

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CheckLog {
    public static void main(String[] args) {
        if (args.length != 0) {
            System.out.println("Usage: java CheckLog");
            System.exit(1);
        }

        File logFile = new File("log.txt");
        File headFile = new File("loghead.txt");

        if (!logFile.exists()) {
            System.out.println("failed: log file missing");
            System.exit(1);
        }
        if (!headFile.exists()) {
            System.out.println("failed: head pointer file missing");
            System.exit(1);
        }

        try (
            BufferedReader logReader = new BufferedReader(new FileReader(logFile));
            BufferedReader headReader = new BufferedReader(new FileReader(headFile))
        ) {
            String line;
            String prevHash = "start";
            int lineNumber = 1;
            String headHash = headReader.readLine();

            while ((line = logReader.readLine()) != null) {
                String[] parts = line.split(" - ", 2);
                if (parts.length != 2) {
                    System.out.println("failed: malformed line at " + lineNumber);
                    System.exit(1);
                }
                String rest = parts[1];
                int spaceIndex = rest.indexOf(' ');
                if (spaceIndex == -1) {
                    System.out.println("failed: malformed line at " + lineNumber);
                    System.exit(1);
                }
                String hash = rest.substring(0, spaceIndex);

                if (!hash.equals(prevHash)) {
                    System.out.println("failed: hash mismatch at line " + (lineNumber - 1));
                    System.exit(1);
                }

                prevHash = computeHash(line);
                lineNumber++;
            }

            if (!prevHash.equals(headHash)) {
                System.out.println("failed: head hash mismatch");
                System.exit(1);
            }

            System.out.println("Valid");
            System.exit(0);
        } catch (IOException e) {
            System.out.println("failed: error reading files - " + e.getMessage());
            System.exit(1);
        }
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