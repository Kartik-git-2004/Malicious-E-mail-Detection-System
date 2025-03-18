package com.emailsecurity.analysis;

import com.emailsecurity.model.Email;
import com.emailsecurity.util.ConfigLoader;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes the text content of emails to identify suspicious patterns,
 * phishing attempts, spam, and social engineering tactics.
 */
public class TextAnalyzer {
    // Common phishing keywords and phrases
    private final List<String> phishingKeywords = Arrays.asList(
            "verify your account", "confirm your account", "update your information",
            "suspicious activity", "security alert", "login attempt", "click here to verify",
            "your account will be suspended", "verify your identity", "urgent action required",
            "validate your account", "account verification", "security notification",
            "unusual sign-in activity", "update your payment information", "confirm your identity"
    );
    
    // Common spam keywords and phrases
    private final List<String> spamKeywords = Arrays.asList(
            "free", "win", "winner", "congratulations", "exclusive offer", "limited time",
            "act now", "special promotion", "cash prize", "discount", "free gift",
            "best price", "great deal", "buy now", "order now", "click below", "cheap",
            "save money", "bonus", "incredible deal", "satisfaction guaranteed", "risk free"
    );
    
    // Social engineering tactics
    private final List<String> socialEngineeringKeywords = Arrays.asList(
            "urgent", "immediate action", "warning", "important", "alert", "attention",
            "critical", "mandatory", "required step", "failure to comply", "legal action",
            "penalty", "fine", "breach", "violation", "restricted", "limited offer",
            "only for you", "selected customer", "confidential"
    );
    
    // Suspicious patterns
    private final List<Pattern> suspiciousPatterns = Arrays.asList(
            // Pattern for obfuscated URLs
            Pattern.compile("\\b(click\\s+here|go\\s+to|visit)\\b(?!.*\\bhttp)", Pattern.CASE_INSENSITIVE),
            
            // Pattern for excessive use of special characters
            Pattern.compile("(\\W{5,})"),
            
            // Pattern for misspelled domains
            Pattern.compile("\\b(amaz[0o]n|g[0o]{2}gle|faceb[0o]{2}k|paypall?|micros[0o]ft)\\b", 
                    Pattern.CASE_INSENSITIVE),
            
            // Pattern for strings with mixed character sets (e.g., Cyrillic chars in Latin text)
            Pattern.compile(".*[\\p{InCyrillic}\\p{InGreek}].*[a-z].*|.*[a-z].*[\\p{InCyrillic}\\p{InGreek}].*", 
                    Pattern.CASE_INSENSITIVE)
    );
    
    // Track detected suspicious keywords for reporting
    private final List<String> detectedSuspiciousKeywords = new ArrayList<>();
    
    /**
     * Constructor to initialize the analyzer with configurations.
     * 
     * @param configLoader Configuration loader for customization
     */
    public TextAnalyzer(ConfigLoader configLoader) {
        // Load additional keywords from configuration if available
        List<String> additionalPhishingKeywords = configLoader.getPhishingKeywords();
        List<String> additionalSpamKeywords = configLoader.getSpamKeywords();
        
        if (additionalPhishingKeywords != null) {
            phishingKeywords.addAll(additionalPhishingKeywords);
        }
        
        if (additionalSpamKeywords != null) {
            spamKeywords.addAll(additionalSpamKeywords);
        }
    }
    
    /**
     * Detect potential phishing attempts in the email.
     * 
     * @param email Email to analyze
     * @return Confidence score for phishing detection (0-100)
     */
    public double detectPhishingAttempt(Email email) {
        // Clear previous detections
        detectedSuspiciousKeywords.clear();
        
        String subject = email.getSubject().toLowerCase();
        String body = email.getBody().toLowerCase();
        
        int matchCount = 0;
        
        // Check for phishing keywords in subject and body
        for (String keyword : phishingKeywords) {
            if (subject.contains(keyword.toLowerCase()) || body.contains(keyword.toLowerCase())) {
                matchCount++;
                detectedSuspiciousKeywords.add("Phishing: " + keyword);
            }
        }
        
        // Check for suspicious patterns
        for (Pattern pattern : suspiciousPatterns) {
            Matcher subjectMatcher = pattern.matcher(subject);
            Matcher bodyMatcher = pattern.matcher(body);
            
            if (subjectMatcher.find()) {
                matchCount++;
                detectedSuspiciousKeywords.add("Suspicious pattern in subject: " + subjectMatcher.group());
            }
            
            while (bodyMatcher.find()) {
                matchCount++;
                detectedSuspiciousKeywords.add("Suspicious pattern in body: " + bodyMatcher.group());
            }
        }
        
        // Check if body contains common password or credential request patterns
        if (body.contains("password") || body.contains("username") || 
            body.contains("login") || body.contains("sign in") || 
            body.contains("credit card") || body.contains("ssn") || 
            body.contains("social security")) {
            matchCount += 2;
            detectedSuspiciousKeywords.add("Credential request");
        }
        
        // Calculate confidence score (capped at 100)
        // More matches increase confidence
        return Math.min(matchCount * 15.0, 100.0);
    }
    
    /**
     * Detect potential spam content in the email.
     * 
     * @param email Email to analyze
     * @return Confidence score for spam detection (0-100)
     */
    public double detectSpam(Email email) {
        String subject = email.getSubject().toLowerCase();
        String body = email.getBody().toLowerCase();
        
        int matchCount = 0;
        
        // Check for spam keywords in subject and body
        for (String keyword : spamKeywords) {
            if (subject.contains(keyword.toLowerCase())) {
                matchCount += 2; // Subject matches weighted higher
                detectedSuspiciousKeywords.add("Spam keyword in subject: " + keyword);
            }
            
            if (body.contains(keyword.toLowerCase())) {
                matchCount++;
                detectedSuspiciousKeywords.add("Spam keyword in body: " + keyword);
            }
        }
        
        // Check for ALL CAPS text segments (common in spam)
        Pattern allCapsPattern = Pattern.compile("\\b[A-Z]{5,}\\b");
        Matcher subjectCapsMatcher = allCapsPattern.matcher(email.getSubject());
        Matcher bodyCapsMatcher = allCapsPattern.matcher(email.getBody());
        
        while (subjectCapsMatcher.find()) {
            matchCount += 2;
            detectedSuspiciousKeywords.add("All caps in subject: " + subjectCapsMatcher.group());
        }
        
        while (bodyCapsMatcher.find()) {
            matchCount++;
            detectedSuspiciousKeywords.add("All caps in body: " + bodyCapsMatcher.group());
        }
        
        // Check for excessive exclamation marks
        long exclamationCount = email.getSubject().chars().filter(ch -> ch == '!').count() +
                               email.getBody().chars().filter(ch -> ch == '!').count();
        
        if (exclamationCount > 3) {
            matchCount += Math.min((int)exclamationCount / 2, 5);
            detectedSuspiciousKeywords.add("Excessive exclamation marks: " + exclamationCount);
        }
        
        // Calculate confidence score (cap at 100)
        return Math.min(matchCount * 10.0, 100.0);
    }
    
    /**
     * Detect social engineering tactics in the email.
     * 
     * @param email Email to analyze
     * @return Confidence score for social engineering detection (0-100)
     */
    public double detectSocialEngineering(Email email) {
        String subject = email.getSubject().toLowerCase();
        String body = email.getBody().toLowerCase();
        
        int matchCount = 0;
        
        // Check for social engineering keywords
        for (String keyword : socialEngineeringKeywords) {
            if (subject.contains(keyword.toLowerCase())) {
                matchCount += 2; // Subject matches weighted higher
                detectedSuspiciousKeywords.add("Social engineering in subject: " + keyword);
            }
            
            if (body.contains(keyword.toLowerCase())) {
                matchCount++;
                detectedSuspiciousKeywords.add("Social engineering in body: " + keyword);
            }
        }
        
        // Check for urgency indicators (time-limited offers)
        Pattern timePattern = Pattern.compile(
                "\\b(today only|hours left|expires today|act now|expires in|limited time|deadline|running out|hurry)\\b", 
                Pattern.CASE_INSENSITIVE);
        
        Matcher subjectTimeMatcher = timePattern.matcher(subject);
        Matcher bodyTimeMatcher = timePattern.matcher(body);
        
        if (subjectTimeMatcher.find()) {
            matchCount += 2;
            detectedSuspiciousKeywords.add("Urgency in subject: " + subjectTimeMatcher.group());
        }
        
        while (bodyTimeMatcher.find()) {
            matchCount++;
            detectedSuspiciousKeywords.add("Urgency in body: " + bodyTimeMatcher.group());
        }
        
        // Check for fear-based messaging
        Pattern fearPattern = Pattern.compile(
                "\\b(risk|threat|danger|warning|alert|security breach|compromise|lose access|account closed)\\b", 
                Pattern.CASE_INSENSITIVE);
        
        Matcher subjectFearMatcher = fearPattern.matcher(subject);
        Matcher bodyFearMatcher = fearPattern.matcher(body);
        
        if (subjectFearMatcher.find()) {
            matchCount += 2;
            detectedSuspiciousKeywords.add("Fear-based message in subject: " + subjectFearMatcher.group());
        }
        
        while (bodyFearMatcher.find()) {
            matchCount++;
            detectedSuspiciousKeywords.add("Fear-based message in body: " + bodyFearMatcher.group());
        }
        
        // Calculate confidence score (cap at 100)
        return Math.min(matchCount * 12.0, 100.0);
    }
    
    /**
     * Get the list of detected suspicious keywords and patterns.
     * 
     * @return List of suspicious text elements
     */
    public List<String> getDetectedSuspiciousKeywords() {
        return detectedSuspiciousKeywords;
    }
} 