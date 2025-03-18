package com.emailsecurity.analysis;

import com.emailsecurity.model.Email;
import com.emailsecurity.model.ThreatReport;
import com.emailsecurity.model.ThreatReport.ThreatType;
import com.emailsecurity.util.ConfigLoader;

/**
 * Main analyzer class that coordinates different analysis components
 * to generate a comprehensive threat report for an email.
 */
public class EmailAnalyzer {
    private final TextAnalyzer textAnalyzer;
    private final LinkAnalyzer linkAnalyzer;
    private final SenderAnalyzer senderAnalyzer;
    private final MachineLearningAnalyzer mlAnalyzer;
    
    /**
     * Constructor initializes all analyzer components.
     * 
     * @param configLoader Configuration loader to provide necessary settings
     */
    public EmailAnalyzer(ConfigLoader configLoader) {
        this.textAnalyzer = new TextAnalyzer(configLoader);
        this.linkAnalyzer = new LinkAnalyzer(configLoader);
        this.senderAnalyzer = new SenderAnalyzer(configLoader);
        this.mlAnalyzer = new MachineLearningAnalyzer(configLoader);
    }
    
    /**
     * Analyze an email using all available analysis components and generate a threat report.
     * 
     * @param email Email to analyze
     * @return A comprehensive threat report
     */
    public ThreatReport analyzeEmail(Email email) {
        // Create a new report for this email
        ThreatReport report = new ThreatReport(email);
        
        // Run all analyzers
        analyzeText(email, report);
        analyzeLinks(email, report);
        analyzeSender(email, report);
        applyMachineLearning(email, report);
        
        // Add generic recommendations based on findings
        addRecommendations(report);
        
        return report;
    }
    
    /**
     * Analyze the text content of the email (subject and body).
     * 
     * @param email Email to analyze
     * @param report Report to update with findings
     */
    private void analyzeText(Email email, ThreatReport report) {
        // Check if text contains phishing indicators
        double phishingScore = textAnalyzer.detectPhishingAttempt(email);
        if (phishingScore > 0) {
            report.addThreat(ThreatType.PHISHING, phishingScore);
        }
        
        // Check if text contains spam indicators
        double spamScore = textAnalyzer.detectSpam(email);
        if (spamScore > 0) {
            report.addThreat(ThreatType.SPAM, spamScore);
        }
        
        // Check for social engineering tactics
        double socialEngineeringScore = textAnalyzer.detectSocialEngineering(email);
        if (socialEngineeringScore > 0) {
            report.addThreat(ThreatType.SOCIAL_ENGINEERING, socialEngineeringScore);
        }
        
        // Add suspicious keywords to the report
        for (String keyword : textAnalyzer.getDetectedSuspiciousKeywords()) {
            report.addSuspiciousKeyword(keyword);
        }
    }
    
    /**
     * Analyze the links in the email body.
     * 
     * @param email Email to analyze
     * @param report Report to update with findings
     */
    private void analyzeLinks(Email email, ThreatReport report) {
        // No links to analyze
        if (email.getExtractedUrls().isEmpty()) {
            return;
        }
        
        boolean hasMaliciousLinks = false;
        double highestConfidence = 0;
        
        // Check each URL
        for (String url : email.getExtractedUrls()) {
            double linkThreatScore = linkAnalyzer.analyzeLinkSafety(url);
            
            if (linkThreatScore > 50) {
                report.addSuspiciousLink(url);
                hasMaliciousLinks = true;
                highestConfidence = Math.max(highestConfidence, linkThreatScore);
            }
        }
        
        // Add threat if malicious links were found
        if (hasMaliciousLinks) {
            report.addThreat(ThreatType.SUSPICIOUS_LINK, highestConfidence);
        }
    }
    
    /**
     * Analyze the sender information.
     * 
     * @param email Email to analyze
     * @param report Report to update with findings
     */
    private void analyzeSender(Email email, ThreatReport report) {
        // Check if sender is suspicious
        double spoofingScore = senderAnalyzer.detectSpoofing(email);
        if (spoofingScore > 0) {
            report.addThreat(ThreatType.SENDER_SPOOFING, spoofingScore);
        }
    }
    
    /**
     * Apply machine learning analysis for additional insights.
     * 
     * @param email Email to analyze
     * @param report Report to update with findings
     */
    private void applyMachineLearning(Email email, ThreatReport report) {
        // Get ML-based classification with confidence
        double[] mlResults = mlAnalyzer.classifyEmail(email);
        
        // If ML predicts malicious with high confidence
        if (mlResults[0] > 0.7) {
            // Add a generic threat with ML-based confidence
            report.addThreat(ThreatType.OTHER, mlResults[0] * 100);
        }
    }
    
    /**
     * Add recommendations based on the threats found.
     * 
     * @param report Report to add recommendations to
     */
    private void addRecommendations(ThreatReport report) {
        // Basic recommendations for all potentially malicious emails
        if (report.isMalicious()) {
            report.addRecommendation("Do not reply to this email");
            
            // Recommendations for specific threat types
            for (ThreatType threatType : report.getThreatConfidence().keySet()) {
                switch (threatType) {
                    case PHISHING:
                        report.addRecommendation("Do not click on any links or buttons in this email");
                        report.addRecommendation("Do not provide any personal information");
                        break;
                        
                    case SUSPICIOUS_LINK:
                        report.addRecommendation("Do not click on any links in this email");
                        report.addRecommendation("If you need to visit the website, type the address directly in your browser");
                        break;
                        
                    case SENDER_SPOOFING:
                        report.addRecommendation("Verify the sender by contacting them through a known, trusted channel");
                        break;
                        
                    case SPAM:
                        report.addRecommendation("Mark the email as spam in your email client");
                        break;
                        
                    case SOCIAL_ENGINEERING:
                        report.addRecommendation("Be cautious of emails creating urgency or strong emotions");
                        break;
                        
                    default:
                        report.addRecommendation("Exercise caution with this email");
                }
            }
        } else {
            report.addRecommendation("No immediate threats detected, but always remain cautious");
        }
    }
} 