package com.emailsecurity.analysis;

import com.emailsecurity.util.ConfigLoader;
import org.apache.commons.validator.routines.UrlValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Analyzes URLs found in emails to identify potentially malicious links
 * based on various patterns and known malicious domains.
 */
public class LinkAnalyzer {
    private final List<String> knownMaliciousDomains;
    private final List<String> commonSpoofedDomains;
    private final Pattern ipAddressPattern;
    private final UrlValidator urlValidator;
    
    /**
     * Constructor to initialize the analyzer with configuration.
     * 
     * @param configLoader Configuration loader for known malicious domains
     */
    public LinkAnalyzer(ConfigLoader configLoader) {
        // Get known malicious domains from configuration
        this.knownMaliciousDomains = configLoader.getMaliciousDomains();
        
        // Common domains that are frequently spoofed
        this.commonSpoofedDomains = new ArrayList<>();
        commonSpoofedDomains.add("google");
        commonSpoofedDomains.add("microsoft");
        commonSpoofedDomains.add("apple");
        commonSpoofedDomains.add("amazon");
        commonSpoofedDomains.add("paypal");
        commonSpoofedDomains.add("facebook");
        commonSpoofedDomains.add("dropbox");
        commonSpoofedDomains.add("linkedin");
        commonSpoofedDomains.add("instagram");
        commonSpoofedDomains.add("twitter");
        commonSpoofedDomains.add("bank");
        commonSpoofedDomains.add("chase");
        commonSpoofedDomains.add("wellsfargo");
        commonSpoofedDomains.add("citibank");
        
        // Pattern to detect raw IP addresses in URLs
        this.ipAddressPattern = Pattern.compile(
                "https?://((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
                Pattern.CASE_INSENSITIVE);
        
        // URL validator for basic validation
        this.urlValidator = new UrlValidator(new String[]{"http", "https"});
    }
    
    /**
     * Analyze a URL to determine if it's potentially malicious.
     * 
     * @param url The URL to analyze
     * @return Threat score (0-100, higher means more likely to be malicious)
     */
    public double analyzeLinkSafety(String url) {
        if (url == null || url.isEmpty()) {
            return 0.0;
        }
        
        double threatScore = 0.0;
        
        // Basic URL validation
        if (!urlValidator.isValid(url)) {
            // Invalid URL format is highly suspicious
            return 90.0;
        }
        
        try {
            URI uri = new URI(url);
            String host = uri.getHost().toLowerCase();
            
            // Check against known malicious domains
            if (knownMaliciousDomains != null) {
                for (String maliciousDomain : knownMaliciousDomains) {
                    if (host.contains(maliciousDomain.toLowerCase())) {
                        return 100.0; // Maximum threat score for known malicious domains
                    }
                }
            }
            
            // Check if URL contains IP address (suspicious)
            if (ipAddressPattern.matcher(url).find() || host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                threatScore += 70.0;
            }
            
            // Check for extremely long host names (often suspicious)
            if (host.length() > 40) {
                threatScore += 40.0;
            }
            
            // Check for suspicious TLDs
            String tld = host.substring(host.lastIndexOf('.') + 1);
            if (isSuspiciousTLD(tld)) {
                threatScore += 30.0;
            }
            
            // Check for URL shortening services
            if (isUrlShortener(host)) {
                threatScore += 25.0;
            }
            
            // Check for domains that look like common ones but are slightly different (typosquatting)
            if (isSpoofedDomain(host)) {
                threatScore += 60.0;
            }
            
            // Check for unusual port numbers
            if (uri.getPort() > 0 && uri.getPort() != 80 && uri.getPort() != 443) {
                threatScore += 25.0;
            }
            
            // Check for excessive subdomains
            int subdomainCount = host.split("\\.").length - 1;
            if (subdomainCount > 3) {
                threatScore += 20.0;
            }
            
            // Check for deceptive URL paths
            String path = uri.getPath();
            if (path != null && !path.isEmpty()) {
                if (path.toLowerCase().contains("login") || 
                    path.toLowerCase().contains("account") || 
                    path.toLowerCase().contains("secure") || 
                    path.toLowerCase().contains("verify")) {
                    threatScore += 15.0;
                }
            }
            
            // Cap the threat score at 100
            return Math.min(threatScore, 100.0);
            
        } catch (URISyntaxException e) {
            // Malformed URL is highly suspicious
            return 85.0;
        }
    }
    
    /**
     * Check if the given TLD (Top Level Domain) is suspicious.
     * 
     * @param tld The TLD to check
     * @return True if the TLD is considered suspicious
     */
    private boolean isSuspiciousTLD(String tld) {
        // List of TLDs often used in phishing/malicious sites
        List<String> suspiciousTLDs = List.of(
                "tk", "ml", "ga", "cf", "gq", "xyz", "top", "info", "live", "online", 
                "site", "stream", "club", "icu", "work", "link"
        );
        
        return suspiciousTLDs.contains(tld.toLowerCase());
    }
    
    /**
     * Check if the host is a known URL shortening service.
     * 
     * @param host The host to check
     * @return True if the host is a URL shortener
     */
    private boolean isUrlShortener(String host) {
        // List of common URL shorteners
        List<String> shorteners = List.of(
                "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
                "rebrand.ly", "cutt.ly", "tiny.cc", "shorte.st", "adf.ly", "bc.vc"
        );
        
        return shorteners.contains(host.toLowerCase());
    }
    
    /**
     * Check if the domain appears to be spoofing a common legitimate domain.
     * 
     * @param host The host to check
     * @return True if the domain appears to be spoofed
     */
    private boolean isSpoofedDomain(String host) {
        // For each common domain, check if this host is a potential spoof
        for (String commonDomain : commonSpoofedDomains) {
            // Skip if the host is exactly the common domain (with potential .com/.org/etc.)
            if (host.equals(commonDomain + ".com") || 
                host.equals(commonDomain + ".org") || 
                host.equals(commonDomain + ".net")) {
                continue;
            }
            
            // Check for Levenshtein distance of 1 (one character difference)
            // or check if the domain contains the common name but with extra characters
            if (calculateLevenshteinDistance(host.toLowerCase(), commonDomain.toLowerCase()) <= 2 ||
                (host.contains(commonDomain) && !host.startsWith("www.") && !host.startsWith(commonDomain + "."))) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Calculate Levenshtein distance between two strings.
     * This helps identify typosquatting domains that differ by just a few characters.
     * 
     * @param s1 First string
     * @param s2 Second string
     * @return The edit distance between the strings
     */
    private int calculateLevenshteinDistance(String s1, String s2) {
        int[][] dp = new int[s1.length() + 1][s2.length() + 1];
        
        for (int i = 0; i <= s1.length(); i++) {
            dp[i][0] = i;
        }
        
        for (int j = 0; j <= s2.length(); j++) {
            dp[0][j] = j;
        }
        
        for (int i = 1; i <= s1.length(); i++) {
            for (int j = 1; j <= s2.length(); j++) {
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(
                        Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                        dp[i - 1][j - 1] + cost
                );
            }
        }
        
        return dp[s1.length()][s2.length()];
    }
} 