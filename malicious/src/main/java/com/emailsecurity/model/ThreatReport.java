package com.emailsecurity.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Contains the results of the email threat analysis with detailed information
 * about detected threats and confidence levels.
 */
public class ThreatReport {
    public enum ThreatType {
        PHISHING,
        SPAM,
        MALWARE,
        SUSPICIOUS_LINK,
        SENDER_SPOOFING,
        SOCIAL_ENGINEERING,
        OTHER
    }
    
    private Email analyzedEmail;
    private boolean isMalicious;
    private double overallThreatScore; // 0-100, higher means more likely to be malicious
    private Map<ThreatType, Double> threatConfidence; // Maps threat types to confidence levels (0-100)
    private List<String> suspiciousLinks;
    private List<String> suspiciousKeywords;
    private List<String> recommendations;
    
    /**
     * Constructor to initialize an empty report for a given email.
     * 
     * @param email The email being analyzed
     */
    public ThreatReport(Email email) {
        this.analyzedEmail = email;
        this.isMalicious = false;
        this.overallThreatScore = 0.0;
        this.threatConfidence = new HashMap<>();
        this.suspiciousLinks = new ArrayList<>();
        this.suspiciousKeywords = new ArrayList<>();
        this.recommendations = new ArrayList<>();
    }
    
    /**
     * Add a detected threat with its confidence level.
     * 
     * @param type The type of threat detected
     * @param confidence Confidence level (0-100)
     */
    public void addThreat(ThreatType type, double confidence) {
        threatConfidence.put(type, confidence);
        
        // Recalculate overall threat score
        updateOverallThreatScore();
    }
    
    /**
     * Add a suspicious link found in the email.
     * 
     * @param link The suspicious URL
     */
    public void addSuspiciousLink(String link) {
        suspiciousLinks.add(link);
    }
    
    /**
     * Add a suspicious keyword found in the email.
     * 
     * @param keyword The suspicious keyword or phrase
     */
    public void addSuspiciousKeyword(String keyword) {
        suspiciousKeywords.add(keyword);
    }
    
    /**
     * Add a recommendation for the user.
     * 
     * @param recommendation Action recommended to the user
     */
    public void addRecommendation(String recommendation) {
        recommendations.add(recommendation);
    }
    
    /**
     * Update the overall threat score based on individual threat confidences.
     */
    private void updateOverallThreatScore() {
        if (threatConfidence.isEmpty()) {
            overallThreatScore = 0.0;
            isMalicious = false;
            return;
        }
        
        // Calculate the average of all threat confidences
        double sum = 0.0;
        for (Double confidence : threatConfidence.values()) {
            sum += confidence;
        }
        
        overallThreatScore = sum / threatConfidence.size();
        
        // Consider email malicious if overall score is above 50
        isMalicious = overallThreatScore > 50.0;
    }
    
    /**
     * Generate a detailed report as a formatted string.
     * 
     * @return Formatted report string
     */
    public String generateDetailedReport() {
        StringBuilder report = new StringBuilder();
        report.append("\n========== EMAIL THREAT ANALYSIS REPORT ==========\n\n");
        
        // Email details
        report.append("Email details:\n");
        report.append("- Sender: ").append(analyzedEmail.getSender()).append("\n");
        report.append("- Subject: ").append(analyzedEmail.getSubject()).append("\n\n");
        
        // Overall assessment
        report.append("Overall assessment:\n");
        report.append("- Malicious: ").append(isMalicious ? "YES" : "NO").append("\n");
        report.append(String.format("- Threat score: %.1f%%\n\n", overallThreatScore));
        
        // Detailed threats
        if (!threatConfidence.isEmpty()) {
            report.append("Detected threats:\n");
            for (Map.Entry<ThreatType, Double> entry : threatConfidence.entrySet()) {
                report.append(String.format("- %s (confidence: %.1f%%)\n", 
                        entry.getKey().toString(), entry.getValue()));
            }
            report.append("\n");
        }
        
        // Suspicious links
        if (!suspiciousLinks.isEmpty()) {
            report.append("Suspicious links:\n");
            for (String link : suspiciousLinks) {
                report.append("- ").append(link).append("\n");
            }
            report.append("\n");
        }
        
        // Suspicious keywords
        if (!suspiciousKeywords.isEmpty()) {
            report.append("Suspicious keywords/phrases:\n");
            for (String keyword : suspiciousKeywords) {
                report.append("- ").append(keyword).append("\n");
            }
            report.append("\n");
        }
        
        // Recommendations
        if (!recommendations.isEmpty()) {
            report.append("Recommendations:\n");
            for (String recommendation : recommendations) {
                report.append("- ").append(recommendation).append("\n");
            }
        }
        
        report.append("\n================================================\n");
        
        return report.toString();
    }
    
    // Getters
    public boolean isMalicious() {
        return isMalicious;
    }
    
    public double getOverallThreatScore() {
        return overallThreatScore;
    }
    
    public Map<ThreatType, Double> getThreatConfidence() {
        return threatConfidence;
    }
    
    public List<String> getSuspiciousLinks() {
        return suspiciousLinks;
    }
    
    public List<String> getSuspiciousKeywords() {
        return suspiciousKeywords;
    }
    
    public List<String> getRecommendations() {
        return recommendations;
    }
    
    public Email getAnalyzedEmail() {
        return analyzedEmail;
    }
} 