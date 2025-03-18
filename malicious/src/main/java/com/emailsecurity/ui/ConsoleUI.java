package com.emailsecurity.ui;

import com.emailsecurity.analysis.EmailAnalyzer;
import com.emailsecurity.model.Email;
import com.emailsecurity.model.ThreatReport;
import com.emailsecurity.parser.EmailParser;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.Scanner;

/**
 * Console-based user interface for the Malicious Email Detection System.
 * Provides a simple command-line interface for users to input emails
 * and view analysis results.
 */
public class ConsoleUI {
    private final Scanner scanner;
    private final EmailParser emailParser;
    private final EmailAnalyzer emailAnalyzer;
    private boolean isRunning;

    /**
     * Constructor to initialize the UI with required components.
     * 
     * @param emailParser Parser for email input
     * @param emailAnalyzer Analyzer for email content
     */
    public ConsoleUI(EmailParser emailParser, EmailAnalyzer emailAnalyzer) {
        this.scanner = new Scanner(System.in);
        this.emailParser = emailParser;
        this.emailAnalyzer = emailAnalyzer;
        this.isRunning = false;
    }

    /**
     * Start the console UI and begin accepting user commands.
     */
    public void start() {
        isRunning = true;
        showWelcomeMessage();

        while (isRunning) {
            showMainMenu();
            int choice = getUserChoice(1, 4);

            switch (choice) {
                case 1:
                    handleManualEmailInput();
                    break;
                case 2:
                    handleFileEmailInput();
                    break;
                case 3:
                    showHelpInformation();
                    break;
                case 4:
                    exitApplication();
                    break;
            }
        }
    }

    /**
     * Display welcome message and system information.
     */
    private void showWelcomeMessage() {
        System.out.println("\n===================================================");
        System.out.println("   WELCOME TO THE MALICIOUS EMAIL DETECTION SYSTEM   ");
        System.out.println("===================================================");
        System.out.println("This system analyzes emails to identify potential threats");
        System.out.println("such as phishing attempts, spam, and malicious links.");
        System.out.println("===================================================\n");
    }

    /**
     * Display the main menu options.
     */
    private void showMainMenu() {
        System.out.println("\n----- MAIN MENU -----");
        System.out.println("1. Analyze email by manual input");
        System.out.println("2. Analyze email from file");
        System.out.println("3. Help");
        System.out.println("4. Exit");
        System.out.print("\nEnter your choice (1-4): ");
    }

    /**
     * Get user choice within a specified range.
     * 
     * @param min Minimum valid choice
     * @param max Maximum valid choice
     * @return User's validated choice
     */
    private int getUserChoice(int min, int max) {
        int choice = -1;
        
        while (choice < min || choice > max) {
            try {
                choice = Integer.parseInt(scanner.nextLine().trim());
                if (choice < min || choice > max) {
                    System.out.print("Invalid choice. Enter a number between " + min + " and " + max + ": ");
                }
            } catch (NumberFormatException e) {
                System.out.print("Invalid input. Enter a number between " + min + " and " + max + ": ");
            }
        }
        
        return choice;
    }

    /**
     * Handle manual email input and analysis.
     */
    private void handleManualEmailInput() {
        System.out.println("\n----- MANUAL EMAIL INPUT -----");
        
        System.out.print("Enter sender email: ");
        String sender = scanner.nextLine().trim();
        
        System.out.print("Enter email subject: ");
        String subject = scanner.nextLine().trim();
        
        System.out.println("Enter email body (type 'END' on a new line to finish):");
        StringBuilder bodyBuilder = new StringBuilder();
        String line;
        
        while (!(line = scanner.nextLine()).equals("END")) {
            bodyBuilder.append(line).append("\n");
        }
        
        String body = bodyBuilder.toString().trim();
        
        // Parse the email
        Email email = emailParser.parseFromUserInput(sender, subject, body);
        
        // Analyze the email
        analyzeAndDisplayReport(email);
    }

    /**
     * Handle email input from a file.
     */
    private void handleFileEmailInput() {
        System.out.println("\n----- EMAIL FROM FILE -----");
        System.out.print("Enter the path to the email file: ");
        String filePath = scanner.nextLine().trim();
        
        if (!emailParser.isValidFile(filePath)) {
            System.out.println("Error: File does not exist or cannot be read.");
            return;
        }
        
        try {
            // Parse the email from file
            Email email = emailParser.parseFromFile(filePath);
            
            // Analyze the email
            analyzeAndDisplayReport(email);
            
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        } catch (MessagingException e) {
            System.out.println("Error parsing email: " + e.getMessage());
        }
    }

    /**
     * Analyze an email and display the threat report.
     * 
     * @param email Email to analyze
     */
    private void analyzeAndDisplayReport(Email email) {
        System.out.println("\nAnalyzing email...");
        
        // Extract and display basic email information
        System.out.println("\nEmail Information:");
        System.out.println("Sender: " + email.getSender());
        System.out.println("Subject: " + email.getSubject());
        System.out.println("URLs found: " + email.getExtractedUrls().size());
        
        // Analyze the email
        ThreatReport report = emailAnalyzer.analyzeEmail(email);
        
        // Display the analysis results
        System.out.println(report.generateDetailedReport());
        
        // Pause before returning to menu
        System.out.print("\nPress Enter to continue...");
        scanner.nextLine();
    }

    /**
     * Display help information about using the system.
     */
    private void showHelpInformation() {
        System.out.println("\n----- HELP INFORMATION -----");
        System.out.println("This system analyzes emails to detect potential threats.");
        System.out.println("\nAnalysis components:");
        System.out.println("1. Text Analysis - Identifies suspicious keywords and patterns");
        System.out.println("2. Link Analysis - Checks URLs for potential threats");
        System.out.println("3. Sender Analysis - Verifies sender information for spoofing");
        System.out.println("4. Machine Learning - Uses patterns to classify emails");
        
        System.out.println("\nHow to use:");
        System.out.println("- Use option 1 to manually input email details");
        System.out.println("- Use option 2 to analyze an email from a file");
        System.out.println("- The system will generate a threat report with recommendations");
        
        System.out.println("\nConfiguration:");
        System.out.println("- You can customize the system by editing files in the 'config/' directory");
        System.out.println("- Add custom keywords, domains, and adjust thresholds");
        
        // Pause before returning to menu
        System.out.print("\nPress Enter to return to the main menu...");
        scanner.nextLine();
    }

    /**
     * Exit the application.
     */
    private void exitApplication() {
        System.out.println("\nThank you for using the Malicious Email Detection System.");
        System.out.println("Goodbye!");
        isRunning = false;
    }
} 