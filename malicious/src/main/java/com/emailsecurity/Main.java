package com.emailsecurity;

import com.emailsecurity.analysis.EmailAnalyzer;
import com.emailsecurity.parser.EmailParser;
import com.emailsecurity.ui.ConsoleUI;
import com.emailsecurity.util.ConfigLoader;

import java.io.IOException;

/**
 * Main application class for the Malicious Email Detection System.
 */
public class Main {
    
    public static void main(String[] args) {
        System.out.println("===== Malicious Email Detection System =====");
        
        // Initialize components
        ConfigLoader configLoader = new ConfigLoader();
        EmailParser emailParser = new EmailParser();
        EmailAnalyzer emailAnalyzer = new EmailAnalyzer(configLoader);
        ConsoleUI ui = new ConsoleUI(emailParser, emailAnalyzer);
        
        try {
            // Load configurations
            configLoader.loadConfigurations();
            System.out.println("System initialized successfully.");
            
            // Start the UI
            ui.start();
            
        } catch (IOException e) {
            System.err.println("Error initializing system: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 