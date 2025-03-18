/**
 * PDF Export functionality for Malicious Email Detection System
 * This file provides functions to generate and download PDF reports
 */

// Wait for DOM to be loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get the PDF export button
    const pdfExportBtn = document.querySelector('.action-btn.pdf-export');
    
    if (pdfExportBtn) {
        pdfExportBtn.addEventListener('click', generatePDF);
    }
});

/**
 * Generate a PDF report from the analysis results
 */
function generatePDF() {
    // Access the jsPDF library
    const { jsPDF } = window.jspdf;
    
    // Create a new PDF document
    const doc = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4'
    });
    
    // Get data for the PDF
    const subject = document.getElementById('email-subject')?.value || 'Unknown Subject';
    const sender = document.getElementById('email-sender')?.value || 'Unknown Sender';
    const threatScore = document.querySelector('.percentage')?.textContent || '0%';
    const verdictEl = document.querySelector('.verdict');
    const verdict = verdictEl ? verdictEl.textContent.trim() : 'No verdict available';
    
    // Get threat categories
    const categories = [];
    document.querySelectorAll('.category-item').forEach(item => {
        const categoryName = item.querySelector('h4')?.textContent || '';
        const categoryDetails = item.querySelector('p')?.textContent || '';
        const riskLevel = item.querySelector('.indicator').classList.contains('high') ? 'High' :
                          item.querySelector('.indicator').classList.contains('medium') ? 'Medium' : 'Low';
        
        categories.push({
            name: categoryName,
            details: categoryDetails,
            risk: riskLevel
        });
    });
    
    // Get detected elements
    const elements = [];
    document.querySelectorAll('.elements-list li').forEach(item => {
        const elementText = item.querySelector('.element-text')?.textContent || '';
        const elementTag = item.querySelector('.element-tag')?.textContent || '';
        
        elements.push({
            text: elementText,
            tag: elementTag
        });
    });
    
    // Start building the PDF
    
    // Add header
    doc.setFillColor(37, 99, 235); // Primary color
    doc.rect(0, 0, 210, 30, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(22);
    doc.text('Email Security Analysis Report', 105, 15, { align: 'center' });
    
    // Add date
    const now = new Date();
    doc.setFontSize(10);
    doc.text(`Generated on: ${now.toLocaleString()}`, 105, 23, { align: 'center' });
    
    // Reset text color for the rest of the document
    doc.setTextColor(30, 41, 59); // Text dark color
    
    // Add email information
    doc.setFontSize(14);
    doc.text('Email Information', 15, 40);
    doc.setFontSize(11);
    doc.text(`Subject: ${subject}`, 15, 48);
    doc.text(`Sender: ${sender}`, 15, 54);
    
    // Add threat score
    doc.setFontSize(14);
    doc.text('Threat Assessment', 15, 65);
    doc.setFontSize(20);
    
    // Set color based on threat score
    const scoreValue = parseInt(threatScore);
    if (scoreValue >= 70) {
        doc.setTextColor(239, 68, 68); // High risk color
    } else if (scoreValue >= 40) {
        doc.setTextColor(245, 158, 11); // Medium risk color
    } else {
        doc.setTextColor(16, 185, 129); // Low risk color
    }
    
    doc.text(`Threat Score: ${threatScore}`, 15, 75);
    
    // Reset text color
    doc.setTextColor(30, 41, 59);
    doc.setFontSize(12);
    doc.text(`Verdict: ${verdict}`, 15, 83);
    
    // Add threat categories
    doc.setFontSize(14);
    doc.text('Threat Categories', 15, 95);
    doc.setFontSize(11);
    
    let yPos = 103;
    categories.forEach(category => {
        // Set color based on risk level
        if (category.risk === 'High') {
            doc.setTextColor(239, 68, 68);
        } else if (category.risk === 'Medium') {
            doc.setTextColor(245, 158, 11);
        } else {
            doc.setTextColor(16, 185, 129);
        }
        
        doc.text(`${category.name} - ${category.risk} Risk`, 15, yPos);
        
        // Reset text color
        doc.setTextColor(30, 41, 59);
        doc.text(category.details, 25, yPos + 6);
        
        yPos += 14;
    });
    
    // Add a line to separate sections
    doc.setDrawColor(200, 200, 200);
    doc.line(15, yPos, 195, yPos);
    yPos += 10;
    
    // Add detected elements
    doc.setFontSize(14);
    doc.text('Detected Elements', 15, yPos);
    yPos += 8;
    doc.setFontSize(11);
    
    // Check if we need a new page
    if (yPos > 250) {
        doc.addPage();
        yPos = 20;
    }
    
    elements.forEach(element => {
        // Check if we need a new page
        if (yPos > 270) {
            doc.addPage();
            yPos = 20;
        }
        
        doc.text(`• ${element.text}`, 15, yPos);
        doc.text(`(${element.tag})`, 160, yPos, { align: 'right' });
        yPos += 8;
    });
    
    // Add footer
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(10);
        doc.setTextColor(100, 100, 100);
        doc.text(`EmailShield - Malicious Email Detection System | Page ${i} of ${pageCount}`, 105, 290, { align: 'center' });
    }
    
    // Download the PDF
    doc.save(`email-analysis-${now.getTime()}.pdf`);
    
    // Show confirmation message
    const confirmMsg = document.createElement('div');
    confirmMsg.className = 'pdf-confirmation';
    confirmMsg.innerHTML = '<i class="fas fa-check-circle"></i> PDF report generated successfully';
    document.body.appendChild(confirmMsg);
    
    // Remove confirmation after 3 seconds
    setTimeout(() => {
        confirmMsg.classList.add('fade-out');
        setTimeout(() => {
            document.body.removeChild(confirmMsg);
        }, 300);
    }, 2700);
} 