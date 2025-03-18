package com.emailsecurity.analysis;

import com.emailsecurity.model.Email;
import com.emailsecurity.util.ConfigLoader;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Provides machine learning-based analysis of emails for malicious content detection.
 * This is a simplified implementation that could be expanded with real ML libraries.
 */
public class MachineLearningAnalyzer {
    private boolean modelLoaded;
    private final Random random; // Used for simulation in this demo
    
    // Keywords used to extract features from emails
    private final List<String> featureKeywords = Arrays.asList(
            "urgent", "verify", "account", "password", "credit card", "click", "confirm",  
"update", "bank", "payment", "free", "win", "congratulations", "lottery",  
"offer", "limited", "alert", "security", "login", "access", "suspend", "recover",  
"validate", "expire", "money", "cash", "prize", "gift", "information", "important",  
"transaction", "balance", "refund", "transfer", "billing", "invoice", "bonus", "jackpot",  
"exclusive", "reward", "promo", "voucher", "deal", "discount", "loan", "wire transfer",  
"guaranteed", "secure", "protection", "breach", "unauthorized", "threat", "problem", "final notice",  
"last chance", "act now", "limited time", "encryption", "encrypted", "multi-factor", "OTP", "authentication",  
"reset", "blocked", "unlock", "activation", "phishing", "scam", "fake", "spyware",  
"malware", "adware", "ransomware", "virus", "trojan", "hacker", "compromised", "identity theft",  
"blacklisted", "lawsuit", "legal action", "penalty", "police", "federal", "investigation", "violation",  
"criminal", "payment required", "overdue", "due payment", "urgent payment", "false", "fraudulent", "impersonation",  
"amazon", "google", "paypal", "apple", "netflix", "microsoft", "facebook", "instagram",  
"whatsapp", "linkedin", "ebay", "walmart", "account update", "account verification", "password reset", "security alert",  
"access denied", "personal information", "social security number", "bank details", "credit score", "investment", "bitcoin", "crypto",  
"withdrawal", "deposit", "interest", "trade", "quick money", "fast cash", "easy money", "millionaire",  
"lotto", "free trial", "risk-free", "special offer", "no cost", "hidden fee", "renew subscription", "auto-renewal",  
"unsubscribe", "unsubscribe now", "unsubscribe link", "fake invoice", "fake refund", "overpayment", "bounced payment", "late fee",  
"hidden charge", "automatic charge", "chargeback", "legal notice", "terms violation", "confidential", "anonymous", "secret",  
"spy", "surveillance", "backdoor", "unauthorized access", "data leak", "data breach", "credit report", "bad credit",  
"insurance claim", "policy update", "coverage expired", "government notice", "IRS", "tax refund", "audit", "settlement",  
"account closure", "password change", "login attempt", "wrong password", "access attempt", "login location", "device login", "email login",  
"email hacked", "email compromised", "security token", "security check", "browser update", "plugin update", "software update", "security patch",  
"domain expired", "hosting issue", "SSL certificate", "server down", "DNS issue", "connection error", "network error", "firewall",  
"proxy", "IP address", "VPN", "VPN access", "anonymous connection", "external connection", "remote access", "remote login",  
"malicious code", "suspicious file", "insecure connection", "https", "http", "login credentials", "username", "password reset",  
"account takeover", "unauthorized charge", "security settings", "fraud prevention", "flagged activity", "blacklist", "white list", "bypass",  
"refund processed", "return processed", "unauthorized refund", "overdue invoice", "customer support", "support ticket", "help desk", "support center",  
"download", "install", "attachment", "open attachment", "file attachment", "compressed file", "zip file", "executable",  
"software installation", "browser extension", "plugin installation", "script execution", "run file", "execute file", "system update", "patch update"  

    );
    
    /**
     * Constructor to initialize the analyzer with configurations.
     * 
     * @param configLoader Configuration loader with settings
     */
    public MachineLearningAnalyzer(ConfigLoader configLoader) {
        // In a real implementation, this would load a trained model
        // For demonstration, we'll simulate model behavior
        this.modelLoaded = true;
        this.random = new Random();
        
        // Get the path to the ML model from config (if available)
        String modelPath = configLoader.getMlModelPath();
        if (modelPath == null || modelPath.isEmpty()) {
            System.out.println("No ML model specified. Using default simulation.");
        } else {
            System.out.println("Loading ML model from: " + modelPath);
            // In a real implementation, this would load the model from the path
        }
    }
    
    /**
     * Classify an email as malicious or safe using machine learning.
     * 
     * @param email Email to classify
     * @return Array with [malicious probability, safe probability]
     */
    public double[] classifyEmail(Email email) {
        if (!modelLoaded) {
            return new double[]{0.0, 1.0}; // Default to safe if model not loaded
        }
        
        // Extract features for the classification
        double[] features = extractFeatures(email);
        
        // In a real implementation, this would use the ML model to classify
        // For demonstration, we'll simulate classification based on features
        return simulateClassification(features);
    }
    
    /**
     * Extract feature vector from email content for ML classification.
     * 
     * @param email Email to extract features from
     * @return Feature vector
     */
    private double[] extractFeatures(Email email) {
        String subject = email.getSubject().toLowerCase();
        String body = email.getBody().toLowerCase();
        
        // Count the number of URLs in the email
        int urlCount = email.getExtractedUrls().size();
        
        // Initialize feature vector
        // [keyword frequency, URL count, special chars, text length...]
        double[] features = new double[featureKeywords.size() + 3];
        
        // Calculate keyword frequency
        for (int i = 0; i < featureKeywords.size(); i++) {
            String keyword = featureKeywords.get(i).toLowerCase();
            int count = 0;
            
            // Count occurrences in subject (weighted higher)
            int index = -1;
            while ((index = subject.indexOf(keyword, index + 1)) != -1) {
                count += 2;
            }
            
            // Count occurrences in body
            index = -1;
            while ((index = body.indexOf(keyword, index + 1)) != -1) {
                count++;
            }
            
            // Normalize by text length
            double textLength = subject.length() + body.length();
            if (textLength > 0) {
                features[i] = (double) count / (textLength / 100.0); // Per 100 chars
            }
        }
        
        // Set other features
        features[featureKeywords.size()] = (double) urlCount;
        features[featureKeywords.size() + 1] = countSpecialChars(subject + body) / 100.0;
        features[featureKeywords.size() + 2] = (subject.length() + body.length()) / 1000.0; // Text length in thousands
        
        return features;
    }
    
    /**
     * Count special characters in text (potential indicators of obfuscation).
     * 
     * @param text Text to analyze
     * @return Count of special characters
     */
    private int countSpecialChars(String text) {
        int count = 0;
        for (char c : text.toCharArray()) {
            if (!Character.isLetterOrDigit(c) && !Character.isWhitespace(c)) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Simulate ML classification based on extracted features.
     * In a real implementation, this would use a trained model.
     * 
     * @param features Feature vector
     * @return Classification probabilities [malicious, safe]
     */
    private double[] simulateClassification(double[] features) {
        // This is a simplified simulation of a ML classification
        // In a real implementation, this would use the actual ML model
        
        // Calculate a weighted sum of features (simplified classifier)
        double maliciousScore = 0.0;
        
        // Keywords that strongly indicate phishing/malicious intent
        for (int i = 0; i < Math.min(15, features.length); i++) {
            maliciousScore += features[i] * 0.05; // Weight for keywords
        }
        
        // URL count is an important feature
        if (features.length > featureKeywords.size()) {
            double urlCount = features[featureKeywords.size()];
            maliciousScore += urlCount * 0.1;
        }
        
        // Special character count
        if (features.length > featureKeywords.size() + 1) {
            double specialChars = features[featureKeywords.size() + 1];
            maliciousScore += specialChars * 0.1;
        }
        
        // Add some randomness to simulation for realism
        maliciousScore += (random.nextDouble() * 0.1) - 0.05;
        
        // Ensure the score is between 0 and 1
        maliciousScore = Math.max(0.0, Math.min(1.0, maliciousScore));
        
        return new double[]{maliciousScore, 1.0 - maliciousScore};
    }
    
    /**
     * In a real implementation, this would train or update the ML model
     * with labeled examples.
     * 
     * @param trainingData List of labeled emails for training
     * @return True if training was successful
     */
    public boolean trainModel(List<Email> trainingData, List<Boolean> labels) {
        // This would be implemented with actual ML library code
        // For demonstration, we'll just return true
        System.out.println("Training model with " + trainingData.size() + " examples...");
        return true;
    }
} 