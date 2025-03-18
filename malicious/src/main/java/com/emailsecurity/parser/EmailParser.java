package com.emailsecurity.parser;

import com.emailsecurity.model.Email;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Parses email content from different input sources into Email objects for analysis.
 */
public class EmailParser {

    /**
     * Parse email from user-input strings (simple email components).
     * 
     * @param sender The sender's email address
     * @param subject The email subject
     * @param body The email body
     * @return An Email object with the provided data
     */
    public Email parseFromUserInput(String sender, String subject, String body) {
        return new Email(sender, subject, body);
    }
    
    /**
     * Parse email from a raw email text file (standard email format).
     * 
     * @param filePath Path to the email file
     * @return An Email object parsed from the file
     * @throws IOException If file reading fails
     * @throws MessagingException If email parsing fails
     */
    public Email parseFromFile(String filePath) throws IOException, MessagingException {
        String content = new String(Files.readAllBytes(Paths.get(filePath)));
        return parseFromRawContent(content);
    }
    
    /**
     * Parse email from raw email content string (standard email format).
     * 
     * @param rawContent Raw email content as a string
     * @return An Email object parsed from the content
     * @throws MessagingException If email parsing fails
     */
    public Email parseFromRawContent(String rawContent) throws MessagingException {
        // Set up empty properties for parsing
        Properties props = new Properties();
        Session session = Session.getDefaultInstance(props, null);
        
        // Parse the raw email content
        MimeMessage mimeMessage = new MimeMessage(session, 
                new ByteArrayInputStream(rawContent.getBytes()));
        
        // Extract sender
        String sender = null;
        if (mimeMessage.getFrom() != null && mimeMessage.getFrom().length > 0) {
            InternetAddress address = (InternetAddress) mimeMessage.getFrom()[0];
            sender = address.getAddress();
        }
        
        // Extract subject
        String subject = mimeMessage.getSubject();
        
        // Extract body (simplified - gets only text content)
        String body = "";
        try {
            Object content = mimeMessage.getContent();
            if (content instanceof String) {
                body = (String) content;
            } else {
                body = "Complex email body (contains attachments or multiple parts)";
            }
        } catch (IOException e) {
            body = "Could not extract email body: " + e.getMessage();
        }
        
        // Create the Email object
        Email email = new Email(sender, subject, body);
        
        // Add headers - fixed to use Enumeration properly
        Enumeration<?> headerEnum = mimeMessage.getMatchingHeaders(new String[]{
                "Reply-To", "Return-Path", "Received", "Message-ID" 
        });
        
        while (headerEnum.hasMoreElements()) {
            String header = headerEnum.nextElement().toString();
            String[] parts = header.split(":", 2);
            if (parts.length == 2) {
                email.addHeader(parts[0].trim(), parts[1].trim());
            }
        }
        
        return email;
    }
    
    /**
     * Check if a file exists and is readable.
     * 
     * @param filePath Path to the file to check
     * @return True if the file exists and is readable
     */
    public boolean isValidFile(String filePath) {
        File file = new File(filePath);
        return file.exists() && file.isFile() && file.canRead();
    }
} 