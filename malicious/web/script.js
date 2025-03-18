/**
 * Malicious Email Detection System - Web Interface
 * JavaScript functionality for the web interface
 */

document.addEventListener('DOMContentLoaded', function() {
    // ==== Tab Switching Logic ====
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons and panes
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            // Add active class to clicked button
            button.classList.add('active');
            
            // Show corresponding tab pane
            const tabId = button.getAttribute('data-tab');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });
    
    // ==== File Upload Logic ====
    const fileUpload = document.getElementById('file-upload');
    const fileName = document.querySelector('.file-name');
    const uploadArea = document.querySelector('.upload-area');
    
    if (fileUpload && fileName && uploadArea) {
        // Handle file selection
        fileUpload.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                fileName.textContent = e.target.files[0].name;
            } else {
                fileName.textContent = 'No file chosen';
            }
        });
        
        // Handle drag and drop
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--primary-color)';
            uploadArea.style.backgroundColor = 'rgba(37, 99, 235, 0.05)';
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = '';
            uploadArea.style.backgroundColor = '';
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '';
            uploadArea.style.backgroundColor = '';
            
            if (e.dataTransfer.files.length > 0) {
                fileUpload.files = e.dataTransfer.files;
                fileName.textContent = e.dataTransfer.files[0].name;
            }
        });
        
        // Click on upload area opens file dialog
        uploadArea.addEventListener('click', () => {
            fileUpload.click();
        });
    }
    
    // ==== Form Submission Logic ====
    const pasteForm = document.getElementById('paste-form');
    const uploadForm = document.getElementById('upload-form');
    const resultsSection = document.getElementById('results-section');
    
    // Handle paste form submission
    if (pasteForm) {
        pasteForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            // Get form values
            const subject = document.getElementById('email-subject').value;
            const sender = document.getElementById('email-sender').value;
            const content = document.getElementById('email-content').value;
            
            // Validate form
            if (!subject || !sender || !content) {
                alert('Please fill in all fields');
                return;
            }
            
            // Simulate API call with loading state
            const analyzeBtn = pasteForm.querySelector('.analyze-btn');
            const originalText = analyzeBtn.innerHTML;
            analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
            analyzeBtn.disabled = true;
            
            // Simulate network delay
            setTimeout(() => {
                // Show results section
                resultsSection.classList.remove('hidden');
                
                // Scroll to results
                resultsSection.scrollIntoView({ behavior: 'smooth' });
                
                // Reset button
                analyzeBtn.innerHTML = originalText;
                analyzeBtn.disabled = false;
                
                // In a real implementation, we would send the data to the server
                // and populate the results section with the response
                updateResultsWithDemoData(subject, sender, content);
            }, 1500);
        });
    }
    
    // Handle upload form submission
    if (uploadForm) {
        uploadForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            // Check if file is selected
            const fileInput = document.getElementById('file-upload');
            if (fileInput.files.length === 0) {
                alert('Please select a file to analyze');
                return;
            }
            
            // Simulate API call with loading state
            const analyzeBtn = uploadForm.querySelector('.analyze-btn');
            const originalText = analyzeBtn.innerHTML;
            analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
            analyzeBtn.disabled = true;
            
            // Simulate network delay
            setTimeout(() => {
                // Show results section
                resultsSection.classList.remove('hidden');
                
                // Scroll to results
                resultsSection.scrollIntoView({ behavior: 'smooth' });
                
                // Reset button
                analyzeBtn.innerHTML = originalText;
                analyzeBtn.disabled = false;
                
                // In a real implementation, we would upload the file to the server
                // and populate the results section with the response
                updateResultsWithDemoData('Email from file', 'file@example.com', 'File content');
            }, 1500);
        });
    }
    
    // ==== Results Actions ====
    const newAnalysisBtn = document.querySelector('.action-btn.new-analysis');
    if (newAnalysisBtn) {
        newAnalysisBtn.addEventListener('click', () => {
            // Hide results section
            resultsSection.classList.add('hidden');
            
            // Reset forms
            if (pasteForm) pasteForm.reset();
            if (uploadForm) {
                uploadForm.reset();
                document.querySelector('.file-name').textContent = 'No file chosen';
            }
            
            // Scroll to top of analysis section
            document.querySelector('.analysis-section').scrollIntoView({ behavior: 'smooth' });
        });
    }
    
    // Report and Safe buttons would typically send data to the server
    const reportBtn = document.querySelector('.action-btn.report');
    const safeBtn = document.querySelector('.action-btn.safe');
    
    if (reportBtn) {
        reportBtn.addEventListener('click', () => {
            alert('Email reported as malicious');
            // In a real implementation, this would send a report to the server
        });
    }
    
    if (safeBtn) {
        safeBtn.addEventListener('click', () => {
            alert('Email marked as safe');
            // In a real implementation, this would send feedback to the server
        });
    }

    // Check if there's a value in the URL that indicates PDF export should be triggered
    // This is used to capture screenshots for PDF generation
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('pdf') && urlParams.get('pdf') === 'true') {
        // This means we're in a special PDF generation mode
        // Hide navigation and action buttons
        document.querySelector('nav')?.classList.add('hidden');
        document.querySelector('.action-buttons')?.classList.add('hidden');
        
        // Show the results section if it's hidden
        document.getElementById('results-section')?.classList.remove('hidden');
        
        // Tell the parent window that the content is ready for PDF generation
        window.parent.postMessage('ready-for-pdf', '*');
    }
});

/**
 * Update the results section with demo data based on the email content
 * In a real implementation, this would be replaced with actual analysis results
 * @param {string} subject - Email subject
 * @param {string} sender - Email sender
 * @param {string} content - Email content
 */
function updateResultsWithDemoData(subject, sender, content) {
    // Check for keywords that might indicate phishing or malicious content
    const phishingKeywords = ['urgent', 'password', 'verify', 'account', 'click', 'link', 'bank'];
    const spamKeywords = ['free', 'win', 'money', 'prize', 'offer', 'discount'];
    
    // Count matches
    const phishingCount = countKeywordMatches(content.toLowerCase(), phishingKeywords);
    const spamCount = countKeywordMatches(content.toLowerCase(), spamKeywords);
    
    // Look for URLs
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const urls = content.match(urlRegex) || [];
    
    // Calculate threat score (in a real implementation, this would come from the backend)
    let threatScore = 0;
    
    // Add points for phishing keywords
    threatScore += phishingCount * 15;
    
    // Add points for spam keywords
    threatScore += spamCount * 5;
    
    // Add points for URLs
    threatScore += urls.length * 10;
    
    // Clamp score to 0-100
    threatScore = Math.min(Math.max(Math.round(threatScore), 0), 100);
    
    // Update UI with results
    updateThreatScore(threatScore);
    updateThreatVerdict(threatScore);
    updateThreatCategories(phishingCount, spamCount, urls.length, sender);
    updateDetectedElements(content, phishingKeywords, urls, sender);
}

/**
 * Count the number of matches for keywords in the content
 * @param {string} content - Content to search in
 * @param {string[]} keywords - Keywords to search for
 * @returns {number} - Number of matches
 */
function countKeywordMatches(content, keywords) {
    let count = 0;
    keywords.forEach(keyword => {
        // Use a regex to count all occurrences
        const regex = new RegExp(keyword, 'gi');
        const matches = content.match(regex);
        if (matches) {
            count += matches.length;
        }
    });
    return count;
}

/**
 * Update the threat score display
 * @param {number} score - Threat score (0-100)
 */
function updateThreatScore(score) {
    // Update percentage text
    const percentageEl = document.querySelector('.percentage');
    if (percentageEl) {
        percentageEl.textContent = `${score}%`;
    }
    
    // Update circle
    const circleEl = document.querySelector('.circle');
    if (circleEl) {
        circleEl.setAttribute('stroke-dasharray', `${score}, 100`);
        
        // Change color based on score
        if (score < 30) {
            circleEl.style.stroke = 'var(--low-risk)';
        } else if (score < 70) {
            circleEl.style.stroke = 'var(--medium-risk)';
        } else {
            circleEl.style.stroke = 'var(--high-risk)';
        }
    }
}

/**
 * Update the threat verdict
 * @param {number} score - Threat score
 */
function updateThreatVerdict(score) {
    const verdictEl = document.querySelector('.verdict');
    if (!verdictEl) return;
    
    // Remove existing classes
    verdictEl.classList.remove('high', 'medium', 'low');
    
    let message = '';
    // Update verdict based on score
    if (score < 30) {
        verdictEl.classList.add('low');
        message = 'Low Risk: This email appears to be safe';
        verdictEl.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
    } else if (score < 70) {
        verdictEl.classList.add('medium');
        message = 'Medium Risk: This email contains some suspicious elements';
        verdictEl.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
    } else {
        verdictEl.classList.add('high');
        message = 'High Risk: This email contains multiple signs of phishing';
        verdictEl.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${message}`;
    }
}

/**
 * Update the threat categories section
 * @param {number} phishingCount - Number of phishing keywords found
 * @param {number} spamCount - Number of spam keywords found
 * @param {number} urlCount - Number of URLs found
 * @param {string} sender - Email sender
 */
function updateThreatCategories(phishingCount, spamCount, urlCount, sender) {
    const categories = document.querySelectorAll('.category-item');
    if (!categories.length) return;
    
    // Update phishing category
    updateCategory(categories[0], phishingCount, 
        phishingCount > 2 ? 'high' : phishingCount > 0 ? 'medium' : 'low',
        phishingCount > 2 ? 'Multiple suspicious keywords detected' :
        phishingCount > 0 ? 'Some suspicious keywords detected' : 'No suspicious keywords detected');
    
    // Update spam category
    updateCategory(categories[1], spamCount,
        spamCount > 3 ? 'high' : spamCount > 1 ? 'medium' : 'low',
        spamCount > 3 ? 'Multiple spam indicators found' :
        spamCount > 1 ? 'Some spam indicators found' : 'No spam indicators found');
    
    // Update malicious URLs category
    updateCategory(categories[2], urlCount,
        urlCount > 1 ? 'high' : urlCount > 0 ? 'medium' : 'low',
        urlCount > 1 ? `Contains ${urlCount} URLs that could be suspicious` :
        urlCount > 0 ? 'Contains 1 URL that could be suspicious' : 'No suspicious URLs detected');
    
    // Update sender reputation (simplified)
    const isSuspicious = /suspicious|unknown|temp|fake/i.test(sender);
    updateCategory(categories[3], isSuspicious ? 1 : 0,
        isSuspicious ? 'high' : 'low',
        isSuspicious ? 'Sender domain appears suspicious' : 'Sender domain appears legitimate');
}

/**
 * Update a single category in the threat categories section
 * @param {Element} categoryEl - Category element
 * @param {number} count - Count of issues
 * @param {string} risk - Risk level (high, medium, low)
 * @param {string} message - Message to display
 */
function updateCategory(categoryEl, count, risk, message) {
    if (!categoryEl) return;
    
    // Update indicator
    const indicator = categoryEl.querySelector('.indicator');
    if (indicator) {
        indicator.className = 'indicator ' + risk;
    }
    
    // Update text
    const textEl = categoryEl.querySelector('p');
    if (textEl) {
        textEl.textContent = message;
    }
}

/**
 * Update the detected elements section
 * @param {string} content - Email content
 * @param {string[]} keywords - Keywords to highlight
 * @param {string[]} urls - URLs found in the email
 * @param {string} sender - Email sender
 */
function updateDetectedElements(content, keywords, urls, sender) {
    const elementsList = document.querySelector('.elements-list');
    if (!elementsList) return;
    
    // Clear existing elements
    elementsList.innerHTML = '';
    
    // Add URLs
    urls.forEach(url => {
        const li = document.createElement('li');
        li.innerHTML = `
            <i class="fas fa-link"></i>
            <span class="element-text">${url}</span>
            <span class="element-tag">Suspicious URL</span>
        `;
        elementsList.appendChild(li);
    });
    
    // Add detected keywords
    const detectedKeywords = [];
    keywords.forEach(keyword => {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
        if (regex.test(content.toLowerCase())) {
            detectedKeywords.push(keyword);
        }
    });
    
    // Add unique keywords (limit to 3)
    const uniqueKeywords = [...new Set(detectedKeywords)].slice(0, 3);
    uniqueKeywords.forEach(keyword => {
        const li = document.createElement('li');
        li.innerHTML = `
            <i class="fas fa-exclamation-circle"></i>
            <span class="element-text">${keyword}</span>
            <span class="element-tag">Suspicious Keyword</span>
        `;
        elementsList.appendChild(li);
    });
    
    // Add sender if it looks suspicious
    if (/suspicious|unknown|temp|fake/i.test(sender)) {
        const li = document.createElement('li');
        li.innerHTML = `
            <i class="fas fa-envelope"></i>
            <span class="element-text">${sender}</span>
            <span class="element-tag">Suspicious Sender</span>
        `;
        elementsList.appendChild(li);
    }
    
    // If no elements were added, show a message
    if (elementsList.children.length === 0) {
        const li = document.createElement('li');
        li.innerHTML = `
            <i class="fas fa-check-circle"></i>
            <span class="element-text">No suspicious elements detected</span>
            <span class="element-tag">Safe</span>
        `;
        elementsList.appendChild(li);
    }
} 