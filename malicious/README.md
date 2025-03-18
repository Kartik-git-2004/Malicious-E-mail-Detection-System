# Malicious Email Detection System

A Java-based system that analyzes email content to identify potential threats such as phishing, spam, or malicious links. The system is designed for intermediate-level Java developers and includes features like text analysis, link scanning, and basic machine learning integration for improved accuracy.

## Features

### Email Input
- Input email content (subject, body, and sender information) via a simple console interface or a text file
- Support for parsing email headers and body text for analysis

### Text Analysis
- Keyword-based detection system to identify common phishing or spam phrases
- Regular expressions to detect suspicious patterns (e.g., fake URLs, excessive special characters)
- Detection of social engineering tactics and urgency indicators

### Link Scanning
- Extraction of all URLs from the email body
- Checking against a list of known malicious domains
- Analysis of URL structure for anomalies (e.g., misspelled domains, unusual subdomains, IP address URLs)
- Detection of URL shortening services

### Sender Verification
- Validation of the sender's email address against known spam or phishing sources
- Detection of inconsistencies in the sender's domain
- Analysis of email headers for spoofing attempts

### Machine Learning Integration
- Basic machine learning model for classifying emails as malicious or safe
- Feature extraction from email content
- Confidence-based scoring for threat assessment

### Detailed Reporting
- Comprehensive threat reports with confidence levels
- Specific recommendations based on detected threats
- Clear presentation of analysis results

## System Architecture

The system is organized into several components:

1. **Email Parser**: Handles the parsing of emails from different input sources
2. **Analysis Components**:
   - TextAnalyzer: Analyzes the text content of emails
   - LinkAnalyzer: Analyzes URLs found in emails
   - SenderAnalyzer: Analyzes sender information
   - MachineLearningAnalyzer: Provides ML-based classification
3. **Configuration Manager**: Loads and manages configurations for the analyzers
4. **User Interface**: Simple console-based interface for interaction

## Getting Started

### Prerequisites
- Java Development Kit (JDK) 11 or higher
- Maven for dependency management

### Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/malicious-email-detector.git
cd malicious-email-detector
```

2. Build the project with Maven:
```
mvn clean package
```

3. Run the application:
```
java -jar target/malicious-email-detector-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## Usage

### Console Interface

The application provides a simple console interface with the following options:

1. **Analyze email by manual input**: Enter sender, subject, and body manually
2. **Analyze email from file**: Provide a path to an email file
3. **Help**: Show information about the system
4. **Exit**: Exit the application

### Example Email Analysis

Example input:
```
Sender: support@fakebank.com
Subject: Urgent: Verify Your Account
Body: Dear customer,

We have detected suspicious activity on your account. Please click here to verify your account: http://fakebank.com/login

If you don't verify within 24 hours, your account will be suspended.

Thank you,
Security Team
```

Example output:
```
========== EMAIL THREAT ANALYSIS REPORT ==========

Email details:
- Sender: support@fakebank.com
- Subject: Urgent: Verify Your Account

Overall assessment:
- Malicious: YES
- Threat score: 85.5%

Detected threats:
- PHISHING (confidence: 90.0%)
- SUSPICIOUS_LINK (confidence: 75.0%)
- SOCIAL_ENGINEERING (confidence: 84.0%)

Suspicious links:
- http://fakebank.com/login

Suspicious keywords/phrases:
- Phishing: verify your account
- Phishing: suspicious activity
- Social engineering in subject: urgent
- Urgency in body: within 24 hours
- Fear-based message in body: account will be suspended

Recommendations:
- Do not reply to this email
- Do not click on any links or buttons in this email
- Do not provide any personal information
- Verify the sender by contacting them through a known, trusted channel
- Be cautious of emails creating urgency or strong emotions

================================================
```

## Configuration

The system uses several configuration files located in the `config/` directory:

- `config.json`: Main configuration file with settings and thresholds
- `phishing_keywords.txt`: List of keywords associated with phishing attempts
- `spam_keywords.txt`: List of keywords associated with spam
- `malicious_domains.txt`: List of known malicious domains
- `trusted_domains.txt`: List of trusted sender domains
- `spam_domains.txt`: List of known spam sender domains

These files are automatically created with default values if they don't exist.

## Customization

### Adding Custom Keywords

You can add custom keywords to the respective text files:

```
# phishing_keywords.txt
verify your account
security alert
update your password
confirm your identity
```

### Adding Known Malicious Domains

Add known malicious domains to the malicious_domains.txt file:

```
# malicious_domains.txt
malicious-domain.com
phishing-site.net
fake-bank.com
```

### Adjusting Thresholds

Modify the thresholds in the config.json file:

```json
{
  "thresholds": {
    "phishing_threshold": 60,
    "spam_threshold": 70,
    "link_threshold": 50
  }
}
```

## Extending the System

### Adding New Analysis Components

1. Create a new analyzer class in the `com.emailsecurity.analysis` package
2. Implement the analysis logic
3. Integrate it with the EmailAnalyzer class

### Improving Machine Learning

1. Replace the simulated ML model with a real ML implementation
2. Train the model with labeled email data
3. Update the feature extraction based on your ML model's requirements

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to the open-source community for providing the libraries used in this project
- Inspired by various email security systems and best practices in email threat detection 