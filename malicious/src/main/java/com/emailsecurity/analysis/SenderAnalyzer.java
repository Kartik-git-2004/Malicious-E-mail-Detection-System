package com.emailsecurity.analysis;

import com.emailsecurity.model.Email;
import com.emailsecurity.util.ConfigLoader;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Analyzes the sender information in emails to detect potential spoofing
 * or other sender-based anomalies.
 */
public class SenderAnalyzer {
    private final List<String> trustedDomains;
    private final List<String> knownSpamDomains;
    private final Pattern validEmailPattern;
    
    /**
     * Constructor to initialize the analyzer with configuration.
     * 
     * @param configLoader Configuration loader for domain lists
     */
    public SenderAnalyzer(ConfigLoader configLoader) {
        // Get trusted and spam domains from configuration
        this.trustedDomains = configLoader.getTrustedDomains();
        this.knownSpamDomains = configLoader.getSpamDomains();
        
        // Pattern for basic email validation
        this.validEmailPattern = Pattern.compile(
                "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}$"
        );
    }
    
    /**
     * Detect possible email sender spoofing.
     * 
     * @param email Email to analyze
     * @return Confidence score for spoofing detection (0-100)
     */
    public double detectSpoofing(Email email) {
        String sender = email.getSender();
        String senderDomain = email.getSenderDomain();
        Map<String, String> headers = email.getHeaders();
        
        // If sender is null or empty, that's highly suspicious
        if (sender == null || sender.isEmpty()) {
            return 100.0;
        }
        
        double spoofingScore = 0.0;
        
        // Check if sender format is valid
        if (!validEmailPattern.matcher(sender).matches()) {
            spoofingScore += 60.0;
        }
        
        // Check if sender domain is in known spam domains
        if (knownSpamDomains != null && senderDomain != null) {
            for (String spamDomain : knownSpamDomains) {
                if (senderDomain.equalsIgnoreCase(spamDomain)) {
                    spoofingScore += 80.0;
                    break;
                }
            }
        }
        
        // Check for header inconsistencies (signs of spoofing)
        spoofingScore += analyzeHeaderInconsistencies(email);
        
        // Check display name for common tactics
        spoofingScore += analyzeDisplayName(sender);
        
        // Check if email is from a trusted domain but not properly authenticated
        if (trustedDomains != null && senderDomain != null) {
            for (String trustedDomain : trustedDomains) {
                if (senderDomain.equalsIgnoreCase(trustedDomain)) {
                    // For trusted domains, check if authentication headers are present
                    // Missing or failed authentication for trusted domains is suspicious
                    if (!hasValidAuthentication(headers)) {
                        spoofingScore += 75.0;
                    }
                    break;
                }
            }
        }
        
        // Check for newly registered domains (if information is available)
        // This would require external API integration in a real implementation
        
        // Cap the score at 100
        return Math.min(spoofingScore, 100.0);
    }
    
    /**
     * Analyze email headers for inconsistencies that might indicate spoofing.
     * 
     * @param email Email to analyze
     * @return Score contribution for header inconsistencies
     */
    private double analyzeHeaderInconsistencies(Email email) {
        double score = 0.0;
        Map<String, String> headers = email.getHeaders();
        String sender = email.getSender();
        
        // If no headers to analyze, can't determine inconsistencies
        if (headers == null || headers.isEmpty()) {
            return 0.0;
        }
        
        // Check Return-Path header (if available)
        String returnPath = headers.get("Return-Path");
        if (returnPath != null) {
            returnPath = returnPath.replaceAll("[<>]", "").trim(); // Clean up the value
            
            // If Return-Path doesn't match sender domain, that's suspicious
            if (!sender.toLowerCase().endsWith(returnPath.toLowerCase()) && 
                !returnPath.toLowerCase().endsWith(email.getSenderDomain().toLowerCase())) {
                score += 40.0;
            }
        }
        
        // Check Reply-To header (if available)
        String replyTo = headers.get("Reply-To");
        if (replyTo != null) {
            // If Reply-To is set to a different domain than sender, it's somewhat suspicious
            if (!replyTo.toLowerCase().contains(email.getSenderDomain().toLowerCase())) {
                score += 30.0;
            }
        }
        
        // Check for multiple Received headers with inconsistent routing
        // This would be more complex in a real implementation
        
        return score;
    }
    
    /**
     * Analyze the sender's display name for common spoofing tactics.
     * 
     * @param sender Complete sender address (may include display name)
     * @return Score contribution for display name analysis
     */
    private double analyzeDisplayName(String sender) {
        double score = 0.0;
        
        // Check for common display name tactics in spoofed emails
        if (sender.toLowerCase().contains("admin") || 
            sender.toLowerCase().contains("support") || 
            sender.toLowerCase().contains("service") || 
            sender.toLowerCase().contains("security") || 
            sender.toLowerCase().contains("help") ||
            sender.toLowerCase().contains("notify") ||
            sender.toLowerCase().contains("no-reply") ||
            sender.toLowerCase().contains("paypal") ||
            sender.toLowerCase().contains("amazon") ||
            sender.toLowerCase().contains("facebook") ||
            sender.toLowerCase().contains("microsoft") ||
            sender.toLowerCase().contains("apple") ||
            sender.toLowerCase().contains("google")) {
            
            // If display name contains a well-known entity but domain doesn't match
            // it's likely someone trying to impersonate a legitimate sender
            score += 25.0;
        }
        
        return score;
    }
    
    /**
     * Check if the email has valid authentication headers.
     * In a real implementation, this would check DKIM, SPF, and DMARC results.
     * 
     * @param headers Email headers
     * @return True if authentication headers are present and valid
     */
    private boolean hasValidAuthentication(Map<String, String> headers) {
        // This is a simplified check - in a real system you'd check actual authentication results
        // For demonstration purposes, we're just checking if authentication headers exist
        
        // Check for Authentication-Results header
        if (headers.containsKey("Authentication-Results")) {
            String authResults = headers.get("Authentication-Results");
            
            // Check if authentication passed
            if (authResults.contains("spf=pass") || 
                authResults.contains("dkim=pass") || 
                authResults.contains("dmarc=pass")) {
                return true;
            }
        }
        
        // Default to false if no valid authentication found
        return false;
    }
} 