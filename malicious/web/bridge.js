/**
 * Bridge between the Java backend and the web interface
 * This file provides functions to communicate with the Java backend
 */

// In a real application, this would use AJAX, WebSockets, or another
// method to communicate with the Java backend. For demonstration purposes,
// we'll provide a simulation that could be replaced with real implementation.

/**
 * Analyze an email using the Java backend
 * @param {Object} emailData - Email data to analyze
 * @param {string} emailData.subject - Email subject
 * @param {string} emailData.sender - Email sender
 * @param {string} emailData.content - Email content
 * @returns {Promise<Object>} - Analysis results
 */
function analyzeEmail(emailData) {
    return new Promise((resolve, reject) => {
        // This would actually make an API call to the Java backend
        // For now, we'll simulate a response after a delay
        setTimeout(() => {
            try {
                // In a real implementation, the response would come from the Java backend
                const result = simulateJavaBackendResponse(emailData);
                resolve(result);
            } catch (error) {
                reject(error);
            }
        }, 1500);
    });
}

/**
 * Upload and analyze an email file
 * @param {File} file - Email file to analyze
 * @returns {Promise<Object>} - Analysis results
 */
function analyzeEmailFile(file) {
    return new Promise((resolve, reject) => {
        // This would actually upload the file to the Java backend
        // For now, we'll simulate reading the file and then analyzing it
        const reader = new FileReader();
        
        reader.onload = function(event) {
            try {
                const content = event.target.result;
                // Parse the email content (simplified)
                const subject = content.match(/Subject: (.*)/i)?.[1] || 'Unknown Subject';
                const sender = content.match(/From: (.*)/i)?.[1] || 'unknown@example.com';
                
                // Analyze the parsed email
                const result = simulateJavaBackendResponse({
                    subject,
                    sender,
                    content
                });
                
                resolve(result);
            } catch (error) {
                reject(error);
            }
        };
        
        reader.onerror = function() {
            reject(new Error('Failed to read file'));
        };
        
        // Read the file as text
        reader.readAsText(file);
    });
}

/**
 * Report an email as malicious to the Java backend
 * @param {string} emailId - ID of the email to report
 * @returns {Promise<boolean>} - Success status
 */
function reportMaliciousEmail(emailId) {
    return new Promise((resolve) => {
        // This would actually make an API call to the Java backend
        setTimeout(() => {
            // Simulate successful reporting
            resolve(true);
        }, 500);
    });
}

/**
 * Mark an email as safe in the Java backend
 * @param {string} emailId - ID of the email to mark as safe
 * @returns {Promise<boolean>} - Success status
 */
function markEmailAsSafe(emailId) {
    return new Promise((resolve) => {
        // This would actually make an API call to the Java backend
        setTimeout(() => {
            // Simulate successful marking
            resolve(true);
        }, 500);
    });
}

/**
 * Get the history of analyzed emails from the Java backend
 * @returns {Promise<Array>} - List of analyzed emails
 */
function getEmailHistory() {
    return new Promise((resolve) => {
        // This would actually make an API call to the Java backend
        setTimeout(() => {
            // Simulate history data
            resolve([
                {
                    id: '1',
                    subject: 'Your account needs attention',
                    sender: 'security@example.com',
                    date: '2023-03-15',
                    threatScore: 85,
                    verdict: 'Malicious'
                },
                {
                    id: '2',
                    subject: 'Meeting reminder',
                    sender: 'hr@company.com',
                    date: '2023-03-14',
                    threatScore: 12,
                    verdict: 'Safe'
                },
                {
                    id: '3',
                    subject: 'Free prize inside!',
                    sender: 'marketing@offers.com',
                    date: '2023-03-12',
                    threatScore: 68,
                    verdict: 'Suspicious'
                }
            ]);
        }, 1000);
    });
}

// HELPER FUNCTIONS

/**
 * Simulate a response from the Java backend
 * This would be replaced with actual API calls in a real implementation
 * @param {Object} emailData - Email data to analyze
 * @returns {Object} - Simulated analysis results
 */
function simulateJavaBackendResponse(emailData) {
    // In a real implementation, this would be the response from the Java backend
    // For now, we'll simulate a response based on the email content
    
    const phishingKeywords = [
        'verify', 'account', 'password', 'bank', 'urgent', 'update', 'security',
        'click', 'link', 'confirm', 'login', 'access', 'suspend'
    ];
    
    const spamKeywords = [
        'free', 'win', 'winner', 'prize', 'offer', 'discount', 'congratulations',
        'money', 'cash', 'limited', 'warranty', 'extended'
    ];
    
    // Combine subject and content for analysis
    const combinedText = (emailData.subject + ' ' + emailData.content).toLowerCase();
    
    // Find phishing keywords
    const phishingMatches = phishingKeywords.filter(keyword => 
        new RegExp(`\\b${keyword}\\b`, 'i').test(combinedText)
    );
    
    // Find spam keywords
    const spamMatches = spamKeywords.filter(keyword => 
        new RegExp(`\\b${keyword}\\b`, 'i').test(combinedText)
    );
    
    // Extract URLs
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const urls = combinedText.match(urlRegex) || [];
    
    // Calculate threat scores
    const phishingScore = Math.min(100, phishingMatches.length * 15);
    const spamScore = Math.min(100, spamMatches.length * 10);
    const urlScore = Math.min(100, urls.length * 20);
    
    // Check sender domain
    const senderParts = emailData.sender.split('@');
    const senderDomain = senderParts.length > 1 ? senderParts[1] : '';
    const suspiciousSenderPatterns = ['temp', 'free', 'fake', 'anonymous', 'mail\\.'];
    const senderSuspicious = suspiciousSenderPatterns.some(pattern => 
        new RegExp(pattern, 'i').test(senderDomain)
    );
    const senderScore = senderSuspicious ? 80 : 20;
    
    // Combine scores with weights
    const totalScore = Math.round(
        (phishingScore * 0.4) + 
        (spamScore * 0.2) + 
        (urlScore * 0.3) + 
        (senderScore * 0.1)
    );
    
    // Determine threat categories
    const threatCategories = {
        phishing: {
            score: phishingScore,
            risk: phishingScore > 70 ? 'high' : phishingScore > 30 ? 'medium' : 'low',
            details: phishingScore > 70 
                ? 'Multiple phishing indicators detected' 
                : phishingScore > 30 
                ? 'Some phishing indicators detected' 
                : 'No significant phishing indicators'
        },
        spam: {
            score: spamScore,
            risk: spamScore > 70 ? 'high' : spamScore > 30 ? 'medium' : 'low',
            details: spamScore > 70 
                ? 'High likelihood of spam content' 
                : spamScore > 30 
                ? 'May contain spam elements' 
                : 'Low probability of spam'
        },
        maliciousUrls: {
            score: urlScore,
            risk: urlScore > 70 ? 'high' : urlScore > 30 ? 'medium' : 'low',
            details: urlScore > 70 
                ? `Contains ${urls.length} potentially malicious URLs` 
                : urlScore > 30 
                ? `Contains URLs that may be suspicious` 
                : urls.length > 0 
                ? `Contains ${urls.length} URL(s) with no known threats` 
                : 'No URLs detected'
        },
        senderReputation: {
            score: senderScore,
            risk: senderScore > 70 ? 'high' : senderScore > 30 ? 'medium' : 'low',
            details: senderScore > 70 
                ? 'Sender appears suspicious' 
                : senderScore > 30 
                ? 'Sender has questionable reputation' 
                : 'Sender appears legitimate'
        }
    };
    
    // Determine overall verdict
    let verdict, verdictDetails;
    if (totalScore >= 70) {
        verdict = 'high';
        verdictDetails = 'High Risk: This email contains multiple signs of phishing or malicious content';
    } else if (totalScore >= 40) {
        verdict = 'medium';
        verdictDetails = 'Medium Risk: This email contains some suspicious elements';
    } else {
        verdict = 'low';
        verdictDetails = 'Low Risk: This email appears to be safe';
    }
    
    // Collect detected elements
    const detectedElements = [];
    
    // Add suspicious URLs
    urls.forEach(url => {
        detectedElements.push({
            type: 'url',
            content: url,
            tag: 'Suspicious URL'
        });
    });
    
    // Add phishing keywords (limit to 3)
    phishingMatches.slice(0, 3).forEach(keyword => {
        detectedElements.push({
            type: 'keyword',
            content: keyword,
            tag: 'Phishing Keyword'
        });
    });
    
    // Add spam keywords (limit to 2)
    spamMatches.slice(0, 2).forEach(keyword => {
        detectedElements.push({
            type: 'keyword',
            content: keyword,
            tag: 'Spam Keyword'
        });
    });
    
    // Add suspicious sender if applicable
    if (senderSuspicious) {
        detectedElements.push({
            type: 'sender',
            content: emailData.sender,
            tag: 'Suspicious Sender'
        });
    }
    
    // Return the analysis results
    return {
        id: 'email_' + Date.now(),
        subject: emailData.subject,
        sender: emailData.sender,
        threatScore: totalScore,
        verdict: verdict,
        verdictDetails: verdictDetails,
        threatCategories: threatCategories,
        detectedElements: detectedElements,
        analyzedAt: new Date().toISOString()
    };
} 