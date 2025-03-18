package com.emailsecurity.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents an email with all its components for analysis.
 */
public class Email {
    private String sender;
    private String senderDomain;
    private String subject;
    private String body;
    private Map<String, String> headers;
    private List<String> extractedUrls;

    /**
     * Constructor with basic email components.
     * 
     * @param sender The email sender address
     * @param subject The email subject line
     * @param body The email body content
     */
    public Email(String sender, String subject, String body) {
        this.sender = sender;
        this.subject = subject;
        this.body = body;
        this.headers = new HashMap<>();
        this.extractedUrls = new ArrayList<>();
        
        // Extract domain from sender
        if (sender != null && sender.contains("@")) {
            this.senderDomain = sender.substring(sender.indexOf('@') + 1);
        }
        
        // Extract URLs from body
        extractUrlsFromBody();
    }

    /**
     * Extract all URLs from the email body using regex.
     */
    private void extractUrlsFromBody() {
        if (body == null) return;
        
        // Pattern to match URLs in the email body
        Pattern urlPattern = Pattern.compile(
                "\\b(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]",
                Pattern.CASE_INSENSITIVE);
        
        Matcher matcher = urlPattern.matcher(body);
        while (matcher.find()) {
            extractedUrls.add(matcher.group());
        }
    }

    /**
     * Add a header to the email.
     * 
     * @param name Header name
     * @param value Header value
     */
    public void addHeader(String name, String value) {
        headers.put(name, value);
    }

    // Getters and setters
    public String getSender() {
        return sender;
    }

    public String getSenderDomain() {
        return senderDomain;
    }

    public String getSubject() {
        return subject;
    }

    public String getBody() {
        return body;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public List<String> getExtractedUrls() {
        return extractedUrls;
    }

    @Override
    public String toString() {
        return "Email{" +
                "sender='" + sender + '\'' +
                ", subject='" + subject + '\'' +
                ", body='" + (body != null ? body.substring(0, Math.min(50, body.length())) + "..." : "null") + '\'' +
                ", urls=" + extractedUrls +
                '}';
    }
} 