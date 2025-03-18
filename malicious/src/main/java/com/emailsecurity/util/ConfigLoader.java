package com.emailsecurity.util;

import org.json.JSONObject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class to load and provide access to configuration settings
 * for the malicious email detection system.
 */
public class ConfigLoader {
    private static final String DEFAULT_CONFIG_PATH = "config/config.json";
    private static final String DEFAULT_PHISHING_KEYWORDS_PATH = "config/phishing_keywords.txt";
    private static final String DEFAULT_SPAM_KEYWORDS_PATH = "config/spam_keywords.txt";
    private static final String DEFAULT_MALICIOUS_DOMAINS_PATH = "config/malicious_domains.txt";
    private static final String DEFAULT_TRUSTED_DOMAINS_PATH = "config/trusted_domains.txt";
    private static final String DEFAULT_SPAM_DOMAINS_PATH = "config/spam_domains.txt";
    private static final String DEFAULT_ML_MODEL_PATH = "models/email_classifier.model";

    private JSONObject config;
    private List<String> phishingKeywords;
    private List<String> spamKeywords;
    private List<String> maliciousDomains;
    private List<String> trustedDomains;
    private List<String> spamDomains;
    private String mlModelPath;

    /**
     * Default constructor that uses default config paths.
     */
    public ConfigLoader() {
        this.config = new JSONObject();
        this.phishingKeywords = new ArrayList<>();
        this.spamKeywords = new ArrayList<>();
        this.maliciousDomains = new ArrayList<>();
        this.trustedDomains = new ArrayList<>();
        this.spamDomains = new ArrayList<>();
        this.mlModelPath = DEFAULT_ML_MODEL_PATH;
    }

    /**
     * Load configurations from files.
     * 
     * @throws IOException If configuration files can't be read
     */
    public void loadConfigurations() throws IOException {
        // Create default config directories and files if they don't exist
        createDefaultConfigIfNeeded();
        
        // Try to load main configuration file
        try {
            Path configPath = Paths.get(DEFAULT_CONFIG_PATH);
            if (Files.exists(configPath)) {
                String configContent = new String(Files.readAllBytes(configPath));
                config = new JSONObject(configContent);
                System.out.println("Loaded main configuration file.");
            }
        } catch (Exception e) {
            System.err.println("Warning: Error loading main configuration. Using defaults. " + e.getMessage());
            // Continue with defaults if main config fails
        }

        // Load keyword lists
        loadKeywordList(DEFAULT_PHISHING_KEYWORDS_PATH, phishingKeywords);
        loadKeywordList(DEFAULT_SPAM_KEYWORDS_PATH, spamKeywords);
        loadKeywordList(DEFAULT_MALICIOUS_DOMAINS_PATH, maliciousDomains);
        loadKeywordList(DEFAULT_TRUSTED_DOMAINS_PATH, trustedDomains);
        loadKeywordList(DEFAULT_SPAM_DOMAINS_PATH, spamDomains);

        // Get ML model path from config if available
        if (config.has("ml_model_path")) {
            mlModelPath = config.getString("ml_model_path");
        }
    }

    /**
     * Create default configuration files if they don't exist.
     * 
     * @throws IOException If files can't be created
     */
    private void createDefaultConfigIfNeeded() throws IOException {
        // Create config directory
        Path configDir = Paths.get("config");
        if (!Files.exists(configDir)) {
            Files.createDirectories(configDir);
        }
        
        // Create models directory
        Path modelsDir = Paths.get("models");
        if (!Files.exists(modelsDir)) {
            Files.createDirectories(modelsDir);
        }

        // Create default config file if it doesn't exist
        Path configFile = Paths.get(DEFAULT_CONFIG_PATH);
        if (!Files.exists(configFile)) {
            JSONObject defaultConfig = new JSONObject();
            defaultConfig.put("ml_model_path", DEFAULT_ML_MODEL_PATH);
            
            // Thresholds for different analysis components
            JSONObject thresholds = new JSONObject();
            thresholds.put("phishing_threshold", 60);
            thresholds.put("spam_threshold", 70);
            thresholds.put("link_threshold", 50);
            defaultConfig.put("thresholds", thresholds);
            
            Files.write(configFile, defaultConfig.toString(2).getBytes());
            System.out.println("Created default configuration file.");
        }

        // Create default keyword files if they don't exist
        createDefaultKeywordFileIfNeeded(DEFAULT_PHISHING_KEYWORDS_PATH, 
                "verify your account\nupdate your information\nsuspicious activity\nlogin attempt");
        
        createDefaultKeywordFileIfNeeded(DEFAULT_SPAM_KEYWORDS_PATH,
                "free\nwin\nwinner\ncongratulations\nbest price\ncash prize");
        
        createDefaultKeywordFileIfNeeded(DEFAULT_MALICIOUS_DOMAINS_PATH,
                "malicious-domain.com\nphishing-site.net\nfake-bank.com");
        
        createDefaultKeywordFileIfNeeded(DEFAULT_TRUSTED_DOMAINS_PATH,
                "google.com\nmicrosoft.com\napple.com\namazon.com");
        
        createDefaultKeywordFileIfNeeded(DEFAULT_SPAM_DOMAINS_PATH,
                "spam-sender.com\nknown-spammer.net");
    }

    /**
     * Create a default keyword file with sample content if it doesn't exist.
     * 
     * @param filePath Path to the file
     * @param defaultContent Default content for the file
     * @throws IOException If file can't be created
     */
    private void createDefaultKeywordFileIfNeeded(String filePath, String defaultContent) throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            Files.write(path, defaultContent.getBytes());
            System.out.println("Created default file: " + filePath);
        }
    }

    /**
     * Load a list of keywords from a file.
     * 
     * @param filePath Path to the keyword file
     * @param targetList List to populate with keywords
     */
    private void loadKeywordList(String filePath, List<String> targetList) {
        try {
            Path path = Paths.get(filePath);
            if (Files.exists(path)) {
                List<String> lines = Files.readAllLines(path);
                for (String line : lines) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                        targetList.add(trimmed);
                    }
                }
                System.out.println("Loaded " + targetList.size() + " entries from " + filePath);
            }
        } catch (IOException e) {
            System.err.println("Warning: Could not load " + filePath + ": " + e.getMessage());
        }
    }

    // Getter methods for configuration values

    /**
     * Get the list of phishing keywords.
     * 
     * @return List of phishing keywords
     */
    public List<String> getPhishingKeywords() {
        return phishingKeywords;
    }

    /**
     * Get the list of spam keywords.
     * 
     * @return List of spam keywords
     */
    public List<String> getSpamKeywords() {
        return spamKeywords;
    }

    /**
     * Get the list of known malicious domains.
     * 
     * @return List of malicious domains
     */
    public List<String> getMaliciousDomains() {
        return maliciousDomains;
    }

    /**
     * Get the list of trusted domains.
     * 
     * @return List of trusted domains
     */
    public List<String> getTrustedDomains() {
        return trustedDomains;
    }

    /**
     * Get the list of known spam sender domains.
     * 
     * @return List of spam domains
     */
    public List<String> getSpamDomains() {
        return spamDomains;
    }

    /**
     * Get the path to the ML model.
     * 
     * @return ML model path
     */
    public String getMlModelPath() {
        return mlModelPath;
    }

    /**
     * Get a threshold value from configuration.
     * 
     * @param thresholdName Name of the threshold
     * @param defaultValue Default value if not found
     * @return Threshold value
     */
    public int getThreshold(String thresholdName, int defaultValue) {
        try {
            if (config.has("thresholds")) {
                JSONObject thresholds = config.getJSONObject("thresholds");
                if (thresholds.has(thresholdName)) {
                    return thresholds.getInt(thresholdName);
                }
            }
        } catch (Exception e) {
            System.err.println("Error reading threshold: " + thresholdName);
        }
        return defaultValue;
    }
} 