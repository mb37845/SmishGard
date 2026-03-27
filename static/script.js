// Example messages for analysis
const examples = {
    1: "URGENT: Your bank account has been suspended due to suspicious activity. Click here to verify your identity: http://secure-bank-update.com/verify",
    2: "FedEx: Your package cannot be delivered. Update your delivery address immediately: http://fedex-delivery-update.net/package-123",
    3: "Apple: Your iCloud account needs verification. Confirm your credentials now: http://apple-icloud-verify.com/login"
};

// Toast notification function
function showToast(message, type = 'error', duration = 5000) {
    // Remove any existing toasts
    const existingToast = document.querySelector('.toast-notification');
    if (existingToast) {
        existingToast.remove();
    }
    
    // Create toast element
    const toast = document.createElement('div');
    toast.className = 'toast-notification';
    
    const icon = type === 'error' ? '⚠️' : '💡';
    const title = type === 'error' ? 'Error' : 'Notice';
    
    // Determine colors based on type
    const bgColor = type === 'error' ? '#fef2f2' : '#fffbeb';
    const borderColor = type === 'error' ? '#ef4444' : '#f59e0b';
    const textColor = type === 'error' ? '#991b1b' : '#92400e';
    
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 9999;
        min-width: 300px;
        max-width: 500px;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        display: flex;
        align-items: center;
        gap: 1rem;
        background: ${bgColor};
        border: 2px solid ${borderColor};
        color: ${textColor};
        animation: slideDown 0.3s ease-out;
    `;
    
    toast.innerHTML = `
        <div style="font-size: 1.5rem; flex-shrink: 0;">${icon}</div>
        <div style="flex: 1;">
            <div style="font-weight: 600; margin-bottom: 0.25rem;">${title}</div>
            <div style="font-size: 0.9rem;">${message}</div>
        </div>
        <button onclick="this.parentElement.remove()" style="background: none; border: none; font-size: 1.25rem; cursor: pointer; padding: 0; color: inherit; opacity: 0.6; transition: opacity 0.2s;">×</button>
    `;
    
    // Add animation keyframes if not already added
    if (!document.getElementById('toast-animation-styles')) {
        const styleSheet = document.createElement('style');
        styleSheet.id = 'toast-animation-styles';
        styleSheet.textContent = `
            @keyframes slideDown {
                from {
                    transform: translateX(-50%) translateY(-100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(-50%) translateY(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(styleSheet);
    }
    
    document.body.appendChild(toast);
    
    // Auto remove after duration
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.animation = 'slideDown 0.3s ease-out reverse';
            setTimeout(() => toast.remove(), 300);
        }
    }, duration);
}

// Escape HTML special characters to prevent XSS

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


// Highlight text based on LIME word analysis - only show predicted class
function highlightTextWithLime(text, predictedWeights, maxWeight, prediction) {
    if (!text || !predictedWeights) return escapeHtml(text);
    
    const words = text.split(/(\s+|[.,!?;:])/);
    
    // Determine color based on prediction
    const isSmishing = prediction === 'smishing';
    
    return words.map(word => {
        const cleanWord = word.toLowerCase().replace(/[^\w]/g, '');
        
        if (!cleanWord || !predictedWeights[cleanWord]) {
            return escapeHtml(word);
        }
        
        const weight = predictedWeights[cleanWord];
        
        // Calculate intensity based on weight
        // Use a more aggressive scaling for better visibility
        const normalizedWeight = weight / maxWeight;
        // Ensure minimum visibility of 30% even for tiny weights
        const intensity = Math.min(Math.max(normalizedWeight * 0.9, 0.3), 0.9);
        
        let backgroundColor, borderColor;
        
        if (isSmishing) {
            // Red highlighting for smishing indicators
            backgroundColor = `rgba(239, 68, 68, ${intensity})`;
            borderColor = `rgba(220, 38, 38, ${Math.min(intensity + 0.2, 1)})`;
        } else {
            // Green highlighting for legitimate indicators
            backgroundColor = `rgba(16, 185, 129, ${intensity})`;
            borderColor = `rgba(5, 150, 105, ${Math.min(intensity + 0.2, 1)})`;
        }
        
        return `<span style="background-color: ${backgroundColor}; padding: 2px 4px; border-radius: 3px; border-bottom: 2px solid ${borderColor}; font-weight: 500; display: inline-block; margin: 1px;">${escapeHtml(word)}</span>`;
    }).join('');
}



// Action guidelines data
const actionGuidelines = {
    'clicked-link': {
        title: 'Clicked on Link',
        color: '#f59e0b',
        immediate: [
            'Close the webpage immediately without entering any information',
            'Do not download anything from the site',
            'Clear your browser cache and cookies',
            'Run a security scan on your device using antivirus software'
        ],
        prevention: [
            'Never click links in unsolicited messages',
            'Verify sender identity through official channels first',
            'Hover over links (on desktop) to preview the actual URL',
            'Look for suspicious URLs (misspellings, unusual domains, random characters)'
        ]
    },
    
    'revealed-credentials': {
        title: 'Revealed Personal Credentials',
        color: '#ef4444',
        immediate: [
            'Change your password immediately on the legitimate platform',
            'Enable two-factor authentication (2FA) if available',
            'Check your account for unauthorized activity or changes',
            'Monitor your account closely for the next few weeks',
            'Consider using a password manager for stronger, unique passwords'
        ],
        prevention: [
            'Never enter credentials through links in messages',
            'Always navigate to websites directly by typing the URL',
            'Legitimate organizations never ask for passwords via SMS',
            'Use unique passwords for each account'
        ]
    },
    'shared-financial': {
        title: 'Shared Financial Information',
        color: '#dc2626',
        immediate: [
            'Contact your bank/card provider immediately to freeze or cancel the card',
            'Request a new card with different numbers',
            'Monitor your bank statements for unauthorized transactions',
            'Report the fraud to your bank\'s fraud department',
            'Consider placing a fraud alert on your credit file',
            'Keep records of all communications and transactions'
        ],
        prevention: [
            'Never provide financial details through SMS links',
            'Banks and financial institutions never request card details via text',
            'Use virtual cards for online transactions when possible',
            'Enable transaction alerts on your accounts'
        ]
    },
    'downloaded-file': {
        title: 'Downloaded/Installed Something',
        color: '#b91c1c',
        immediate: [
            'Do not open or run the downloaded file',
            'Uninstall the application immediately if already installed',
            'Put your device in airplane mode to prevent data transmission',
            'Run a full antivirus/anti-malware scan',
            'Change passwords for important accounts from a different, secure device',
            'Consider factory resetting your device if malware is detected',
            'Back up important data before reset'
        ],
        prevention: [
            'Never download files from unknown SMS links',
            'Only install apps from official app stores',
            'Check app permissions before installing',
            'Keep your device operating system and security software updated'
        ]
    },
    'shared-personal': {
        title: 'Provided Personal Information',
        color: '#ea580c',
        immediate: [
            'Document exactly what information was shared',
            'Monitor for identity theft signs (unusual account activity, unexpected bills)',
            'Consider placing a fraud alert or credit freeze with credit bureaus',
            'Report the incident to relevant authorities (consumer protection, data protection)',
            'Be alert for follow-up scams targeting you',
            'Inform organizations that may be affected (employer, government agencies)'
        ],
        prevention: [
            'Never share personal documents or ID numbers via SMS',
            'Government and official agencies communicate through official channels',
            'Verify requests by contacting organizations directly using official contact information'
        ]
    },
    'replied-message': {
        title: 'Replied to Message',
        color: '#f59e0b',
        immediate: [
            'Block the sender immediately',
            'Do not respond to any follow-up messages',
            'Report the number to your mobile carrier',
            'Be prepared for increased spam/scam messages',
            'Change phone number only if harassment continues severely'
        ],
        prevention: [
            'Never reply to suspicious messages',
            'Replying confirms your number is active to scammers',
            'Use "Report Spam" feature in your messaging app'
        ]
    },
    'made-payment': {
        title: 'Made a Payment',
        color: '#b91c1c',
        immediate: [
            'Contact your bank/payment provider immediately to attempt reversal',
            'File a fraud report with your financial institution',
            'Document the transaction (screenshots, receipts, messages)',
            'Report to local law enforcement and cybercrime units',
            'Report to consumer protection agencies',
            'Consider legal advice if large amounts are involved',
            'Monitor accounts for additional unauthorized transactions'
        ],
        prevention: [
            'Never send money based on SMS requests',
            'Verify payment requests through independent communication channels',
            'Be skeptical of urgent payment demands',
            'Use secure, traceable payment methods for legitimate transactions'
        ]
    },
    'scanned-qr': {
        title: 'Scanned QR Code',
        color: '#ea580c',
        immediate: [
            'If it opened a website, close it immediately and don\'t enter information',
            'If it initiated a payment, contact your payment provider to cancel',
            'If it downloaded something, follow the "Downloaded/Installed" guidelines',
            'Check your device for unauthorized apps or changes',
            'Run security scan on your device'
        ],
        prevention: [
            'Never scan QR codes from unsolicited messages',
            'Use QR scanner apps that preview URLs before opening',
            'Be cautious of QR codes requesting immediate payments'
        ]
    },
    'called-number': {
        title: 'Called a Number',
        color: '#f59e0b',
        immediate: [
            'Hang up immediately if they ask for personal information',
            'Do not provide any details during the call',
            'Block the number',
            'If you shared information during the call, follow relevant guidelines',
            'Report the number to your carrier and authorities'
        ],
        prevention: [
            'Never call numbers from suspicious SMS messages',
            'Look up official contact numbers independently',
            'Legitimate organizations don\'t pressure you during calls'
        ]
    },
    'no-action': {
        title: 'Just Received (No Action Yet)',
        color: '#10b981',
        immediate: [
            'Delete the message',
            'Block the sender',
            'Report as spam/phishing to your mobile carrier',
            'Report to relevant authorities (anti-fraud agencies, consumer protection)',
            'Warn friends and family about similar scams'
        ],
        prevention: [
            'Trust your instincts—if something feels wrong, it probably is',
            'Verify suspicious messages through official channels',
            'Stay informed about current scam trends',
            'Share knowledge with others to protect your community'
        ]
    }
};

let selectedAction = null;

// Analysis Functions
function loadExample(exampleId) {
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.value = examples[exampleId];
    }
}

async function analyzeMessageML() {
    const messageInput = document.getElementById('messageInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loading = document.getElementById('loading');
    const resultsPanel = document.getElementById('resultsPanel');
    
    if (!messageInput) return;
    
    const message = messageInput.value.trim();
    
    // Check for empty message
    if (!message) {
        showToast('Please enter a message to analyze', 'warning');
        return;
    }

    // Show loading state
    analyzeBtn.disabled = true;
    if (loading) loading.classList.remove('hidden');
    if (resultsPanel) resultsPanel.classList.add('hidden');

    // Hide action buttons and guidelines
    const actionButtonsSection = document.getElementById('actionButtonsSection');
    const guidelinesSection = document.getElementById('guidelinesSection');
    if (actionButtonsSection) actionButtonsSection.classList.add('hidden');
    if (guidelinesSection) guidelinesSection.classList.add('hidden');
    selectedAction = null;

    const btnText = analyzeBtn.querySelector('.btn-text');
    const btnLoading = analyzeBtn.querySelector('.btn-loading');
    if (btnText && btnLoading) {
        btnText.classList.add('hidden');
        btnLoading.classList.remove('hidden');
    }

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                message: message,
                include_lime: true
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Analysis failed');
        }

        const analysis = await response.json();
        console.log('Analysis response:', analysis);
        displayMLResults(analysis);
        
    } catch (error) {
        console.error('Error:', error);

        let errorMessage = 'An unexpected error occurred. Please try again.';
        
        if (error.message) {
            if (error.message.includes('at least') || 
                error.message.includes('too long') || 
                error.message.includes('characters')) {
                errorMessage = error.message;
            } else if (error.message === 'Analysis failed') {
                errorMessage = 'Unable to analyze the message. Please check your connection.';
            } else if (error.message.includes('fetch')) {
                errorMessage = 'Network error. Please check your internet connection.';
            }
        }
        
        // Show toast notification
        showToast(errorMessage, 'error');

    } finally {
        analyzeBtn.disabled = false;
        if (loading) loading.classList.add('hidden');
        if (btnText && btnLoading) {
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
        }
    }
}

function displayMLResults(analysis) {
    const resultsPanel = document.getElementById('resultsPanel');
    const classificationBadge = document.getElementById('classificationBadge');
    const classificationDetails = document.getElementById('classificationDetails');
    const insightsGrid = document.getElementById('insightsGrid');
    const explanation = document.getElementById('explanation');
    const safetyTips = document.getElementById('safetyTips');

    if (!resultsPanel) return;

    const isSmishing = analysis.prediction === 'smishing';
    const translation = analysis.translation;
    const isTranslated = translation && translation.needs_translation;
    const isUrlOverride = analysis.url_override === true;
    const hasConflict = analysis.url_model_conflict === true;
    
    // Update classification badge
    if (classificationBadge) {
        classificationBadge.textContent = isSmishing ? '⚠️ SMISHING DETECTED' : '✅ APPEARS LEGITIMATE';
        classificationBadge.className = `classification-badge ${isSmishing ? 'smishing' : 'ham'}`;
    }
    
    // Build classification details
    let detailsHTML = '';
    
    if (isUrlOverride) {
        // VirusTotal override case - show only VirusTotal info
        detailsHTML = `
            <div class="override-message-box">
                <h5>Detection Method: VirusTotal URL Analysis</h5>
                <p><strong>${analysis.override_message}</strong></p>
            </div>
            <p><strong>🔗 Harmful URLs Found:</strong> ${analysis.harmful_url_details.count}</p>
            <p><strong>🚨 Malicious Flags:</strong> ${analysis.harmful_url_details.total_malicious_flags} security engine(s)</p>
            <p><strong>⚠️ Suspicious Flags:</strong> ${analysis.harmful_url_details.total_suspicious_flags} security engine(s)</p>
        `;
    } else {
        // Normal AI prediction case
        const confidence = analysis.confidence;
        detailsHTML = `
            <p><strong>🤖 AI Model:</strong> ${analysis.model_used || 'Fine-tuned DistilBERT'}</p>
            <p><strong>📊 Confidence:</strong> ${(confidence * 100).toFixed(1)}% (${analysis.confidence_level})</p>
            ${analysis.probabilities ? `
                <p><strong>🎯 Probability Breakdown:</strong> Legitimate: ${(analysis.probabilities.ham * 100).toFixed(1)}% | Smishing: ${(analysis.probabilities.smishing * 100).toFixed(1)}%</p>
            ` : ''}
        `;
        
        // Add conflict message if model says smishing but URLs are clean
        if (hasConflict) {
            detailsHTML += `
                <div class="conflict-message-box">
                    <h5>Mixed Signals Detected</h5>
                    <p>${analysis.conflict_message}</p>
                </div>
            `;
        }
    }
    
    if (classificationDetails) {
        classificationDetails.innerHTML = detailsHTML;
    }
    
    // Build insights grid (only show for non-override cases)
    if (insightsGrid && !isUrlOverride) {
        insightsGrid.innerHTML = `
            <div class="insight-card model-card">
                <div class="insight-icon">🤖</div>
                <h5>AI Model</h5>
                <p>${analysis.model_used || 'DistilBERT'}</p>
            </div>
            <div class="insight-card confidence-card">
                <div class="insight-icon">📈</div>
                <h5>Confidence</h5>
                <p>${(analysis.confidence * 100).toFixed(1)}%</p>
            </div>
            ${analysis.urls_found !== undefined ? `
                <div class="insight-card urls-card">
                    <div class="insight-icon">🔗</div>
                    <h5>URLs Found</h5>
                    <p>${analysis.urls_found}</p>
                </div>
            ` : ''}
        `;
    } else if (insightsGrid && isUrlOverride) {
        // Show simplified insights for URL override
        insightsGrid.innerHTML = `
            <div class="insight-card urls-card">
                <div class="insight-icon">🔗</div>
                <h5>Harmful URLs</h5>
                <p>${analysis.harmful_url_details.count}</p>
            </div>
            <div class="insight-card malicious-card">
                <div class="insight-icon">🚨</div>
                <h5>Malicious Flags</h5>
                <p>${analysis.harmful_url_details.total_malicious_flags}</p>
            </div>
            <div class="insight-card detection-card">
                <div class="insight-icon">🔍</div>
                <h5>Detection Method</h5>
                <p>VirusTotal</p>
            </div>
        `;
    }

    // Build explanation section
    if (explanation) {
        let virusTotalSection = '';
        
        if (analysis.url_scan_results && analysis.url_scan_results.length > 0) {
            virusTotalSection = `
                <div style="margin-top: 1.5rem; padding: 1.25rem; background: #f8fafc; border-radius: 8px; border-left: 4px solid #3b82f6;">
                    <h4 style="color: #1e40af; margin-bottom: 1rem; font-size: 1.1rem; display: flex; align-items: center; gap: 0.5rem;">
                        <span>🔍</span>
                        <span>VirusTotal URL Scan Results</span>
                    </h4>
                    
                    <div style="margin-bottom: 0.75rem;">
                        <p style="margin: 0; font-size: 0.95rem; color: #1f2937;">
                            <strong>URLs Found:</strong> ${analysis.urls_found}
                        </p>
                    </div>
                    
                    <div style="margin-top: 1rem;">
                        ${analysis.url_scan_results.map((result, index) => {
                            if (result.error) {
                                return `
                                    <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 6px; border: 1px solid #e5e7eb;">
                                        <div style="margin-bottom: 0.5rem;">
                                            <p style="font-size: 0.9rem; color: #374151; font-weight: 600; margin: 0;">URL ${index + 1}:</p>
                                            <p style="font-size: 0.85rem; color: #6b7280; word-break: break-all; margin: 0;">${escapeHtml(result.url)}</p>
                                        </div>
                                        <p style="color: #ef4444; margin: 0.5rem 0 0 0; font-size: 0.9rem;">⚠️ Error: ${escapeHtml(result.error)}</p>
                                    </div>
                                `;
                            }
                            
                            const statusColor = result.is_harmful ? '#ef4444' : '#10b981';
                            const statusIcon = result.is_harmful ? '🔴' : '🟢';
                            
                            return `
                                <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 6px; border: 2px solid ${result.is_harmful ? '#fee2e2' : '#d1fae5'};">
                                    <div style="margin-bottom: 0.75rem;">
                                        <p style="font-size: 0.9rem; color: #374151; font-weight: 600; margin: 0 0 0.25rem 0;">URL ${index + 1}:</p>
                                        <p style="font-size: 0.85rem; color: #6b7280; word-break: break-all; margin: 0;">${result.url}</p>
                                    </div>
                                    
                                    <p style="color: ${statusColor}; font-weight: bold; margin: 0; font-size: 1rem;">
                                        ${statusIcon} Status: ${result.status}
                                    </p>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            `;
        } else if (analysis.urls_found === 0) {
            virusTotalSection = `
                <div style="margin-top: 1.5rem; padding: 1rem; background: #f0fdf4; border-radius: 8px; border-left: 4px solid #10b981;">
                    <p style="color: #047857; margin: 0; font-size: 0.95rem;">ℹ️ No URLs detected in this message</p>
                </div>
            `;
        }

        let limeSection = '';
        // Only show LIME for non-override cases
        if (!isUrlOverride && analysis.lime_explanation && analysis.lime_explanation.explanation_available) {
            const messageInput = document.getElementById('messageInput');
            const originalMessage = messageInput ? messageInput.value : '';
           
            if (isTranslated) {
                limeSection = generateSimplifiedDualLanguageVisualization(
                    analysis.lime_explanation,
                    translation.original,
                    translation.translated,
                    analysis.prediction
                );
            } else {
                limeSection = generateLimeVisualization(
                    analysis.lime_explanation, 
                    originalMessage, 
                    analysis.prediction
                );
            }
        }
        
        explanation.innerHTML = `
            <h4>📊 Analysis Breakdown</h4>
            ${isTranslated ? `
                <div style="margin-bottom: 1rem; padding: 0.75rem; background: #e0f2fe; border-radius: 6px; border-left: 3px solid #0284c7;">
                    <p style="margin: 0; color: #075985; font-size: 0.9rem;">
                        🌍 <strong>Language Detected:</strong> Arabic → Translated to English for analysis
                    </p>
                </div>
            ` : ''}
            ${isUrlOverride ? `
                <div style="margin-bottom: 1rem; padding: 1rem; background: #fef2f2; border-radius: 8px; border-left: 3px solid #ef4444;">
                    <p style="margin: 0; color: #991b1b; font-size: 0.95rem; font-weight: 600;">
                        🔍 This message was classified based on URL analysis only. Text-based AI analysis was not performed because VirusTotal detected harmful URLs.
                    </p>
                </div>
            ` : ''}
            ${limeSection}
            ${virusTotalSection}
        `;
    }

    // Update safety tips
    if (safetyTips) {
        let vtWarning = '';
        if (analysis.url_scan_results) {
            const harmfulUrls = analysis.url_scan_results.filter(r => r.is_harmful);
            if (harmfulUrls.length > 0) {
                vtWarning = '<li style="color: #dc2626; font-weight: bold;">⚠️ <strong>CRITICAL:</strong> VirusTotal detected malicious URLs!</li>';
            }
        }
        
        safetyTips.innerHTML = `
            <h4>🛡️ Safety Recommendations</h4>
            <ul style="list-style: none; padding: 0;">
                ${vtWarning}
                ${isSmishing ? 
                    '<li>🚫 <strong>Do not engage</strong> with this message</li>' +
                    '<li>🔗 <strong>Do not click</strong> any links in the message</li>' +
                    '<li>📞 <strong>Verify directly</strong> with the organization using official contact methods</li>' +
                    '<li>🗑️ <strong>Delete</strong> the message immediately</li>' +
                    '<li>🛡️ <strong>Stay vigilant:</strong> Always verify unexpected messages through official channels</li>' :
                    '<li>✅ This message appears <strong>legitimate</strong></li>' +
                    '<li>🔍 Still practice <strong>caution</strong> when clicking links</li>' +
                    '<li>📱 <strong>Verify</strong> with the organization if unsure</li>' +
                    '<li>💡 <strong>Remember:</strong> Better safe than sorry - when in doubt, verify through official channels</li>'
                }
            </ul>
        `;
    }

    resultsPanel.classList.remove('hidden');
    
    // Only show action buttons for smishing cases
    if (isSmishing) {
        showActionButtons();
    }
}

function generateSimplifiedDualLanguageVisualization(limeData, arabicText, englishText, prediction) {
    const predictedWeights = limeData.predicted_weights || {};
    const maxWeight = limeData.max_weight || 1;
    const minWordLength = limeData.min_word_length || 3;
    const isSmishing = prediction === 'smishing';
    
    const highlightedEnglish = highlightTextWithLime(englishText, predictedWeights, maxWeight, prediction);
    
    return `
        <div class="lime-explanation-container" style="margin-top: 1.5rem; padding: 1.25rem; background: linear-gradient(135deg, #fefce8 0%, #fef3c7 100%); border-radius: 10px; border-left: 4px solid #eab308; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
            <h4 style="color: #854d0e; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem; font-size: 1.1rem;">
                <span>🔬</span> 
                <span>AI Explainability - Why This Classification?</span>
            </h4>
            
            <div style="margin-bottom: 1rem; padding: 1rem; background: #fff3cd; border-radius: 8px; border-left: 3px solid #ff9800;">
                <p style="margin: 0; color: #e65100; font-weight: 600;">
                    🌍 <strong>Note:</strong> Your message was in Arabic. We translated it to English for AI analysis.
                </p>
            </div>
            
            <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; border-left: 3px solid #3b82f6;">
                <p style="margin: 0 0 0.75rem 0; font-size: 0.95rem; color: #1e3a8a; font-weight: 600;">
                    💡 How to read the highlights:
                </p>
                <div style="display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.9rem;">
                    ${isSmishing ? `
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="background-color: rgba(239, 68, 68, 0.5); padding: 3px 10px; border-radius: 4px; font-weight: 500; border-bottom: 2px solid rgba(220, 38, 38, 0.5);">Red/Orange</span>
                            <span style="color: #374151;">= Words indicating <strong>SMISHING</strong> threats</span>
                        </div>
                    ` : `
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="background-color: rgba(16, 185, 129, 0.5); padding: 3px 10px; border-radius: 4px; font-weight: 500; border-bottom: 2px solid rgba(5, 150, 105, 0.5);">Green</span>
                            <span style="color: #374151;">= Words indicating <strong>LEGITIMATE</strong> content</span>
                        </div>
                    `}
                    <div style="margin-top: 0.25rem; padding: 0.5rem; background: #f0f9ff; border-radius: 4px; color: #075985; font-size: 0.85rem;">
                        <strong>Note:</strong> Only words with ${minWordLength}+ characters are highlighted
                    </div>
                </div>
            </div>
            
            <div style="background: white; padding: 1rem; border-radius: 8px; border: 2px solid #e5e7eb; margin-bottom: 1rem;">
                <div style="margin-bottom: 0.75rem; font-weight: 600; color: #374151; font-size: 0.85rem; text-transform: uppercase; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem;">
                    📱 Your Original Message (Arabic):
                </div>
                <div style="color: #1f2937; line-height: 1.9; font-size: 0.95rem; direction: rtl; text-align: right; padding: 0.5rem; background: #f9fafb; border-radius: 4px;">
                    ${escapeHtml(arabicText)}
                </div>
                <p style="margin-top: 0.75rem; font-size: 0.85rem; color: #6b7280; font-style: italic;">
                    ⚠️ Note: Arabic text shown for reference only. AI analysis performed on English translation below.
                </p>
            </div>
            
            <div style="background: white; padding: 1rem; border-radius: 8px; border: 2px solid #e5e7eb;">
                <div style="margin-bottom: 0.75rem; font-weight: 600; color: #374151; font-size: 0.85rem; text-transform: uppercase; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem;">
                    🔤 Translated to English (AI Analysis):
                </div>
                <div style="color: #1f2937; line-height: 1.9; font-size: 0.95rem;">
                    ${highlightedEnglish}
                </div>
            </div>
            
            <div style="margin-top: 1rem; padding: 0.75rem; background: ${isSmishing ? '#fef2f2' : '#f0fdf4'}; border-radius: 6px; border-left: 3px solid ${isSmishing ? '#ef4444' : '#10b981'};">
                <p style="margin: 0; font-size: 0.9rem; color: ${isSmishing ? '#7f1d1d' : '#065f46'};">
                    <strong>🎯 Final Verdict:</strong> The AI identified key ${isSmishing ? 'threat indicators' : 'legitimate patterns'} and classified this as <strong style="text-transform: uppercase;">${prediction}</strong>
                </p>
            </div>
        </div>
    `;
}

function generateLimeVisualization(limeData, originalMessage, actualPrediction) {
    if (!limeData || !limeData.explanation_available) {
        return '';
    }

    const predictedWeights = limeData.predicted_weights || {};
    const maxWeight = limeData.max_weight || 1;
    const minWordLength = limeData.min_word_length || 3;
    const isSmishing = actualPrediction === 'smishing';

    const highlightedHTML = highlightTextWithLime(originalMessage, predictedWeights, maxWeight, actualPrediction);

    return `
        <div class="lime-explanation-container" style="margin-top: 1.5rem; padding: 1.25rem; background: linear-gradient(135deg, #fefce8 0%, #fef3c7 100%); border-radius: 10px; border-left: 4px solid #eab308; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
            <h4 style="color: #854d0e; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem; font-size: 1.1rem;">
                <span></span> 
                <span>AI Explainability - Why This Classification?</span>
            </h4>
            
            <div style="margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; border-left: 3px solid #3b82f6;">
                <p style="margin: 0 0 0.75rem 0; font-size: 0.95rem; color: #1e3a8a; font-weight: 600;">
                    How to read the highlights:
                </p>
                <div style="display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.9rem;">
                    ${isSmishing ? `
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="background-color: rgba(239, 68, 68, 0.5); padding: 3px 10px; border-radius: 4px; font-weight: 500; border-bottom: 2px solid rgba(220, 38, 38, 0.5);">Red/Orange</span>
                            <span style="color: #374151;">= Words indicating <strong>SMISHING</strong> threats</span>
                        </div>
                    ` : `
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="background-color: rgba(16, 185, 129, 0.5); padding: 3px 10px; border-radius: 4px; font-weight: 500; border-bottom: 2px solid rgba(5, 150, 105, 0.5);">Green</span>
                            <span style="color: #374151;">= Words indicating <strong>LEGITIMATE</strong> content</span>
                        </div>
                    `}
                    <div style="margin-top: 0.25rem; padding: 0.5rem; background: #f0f9ff; border-radius: 4px; color: #075985; font-size: 0.85rem;">
                        <strong>Note:</strong> Only words with ${minWordLength}+ characters are highlighted. Brighter colors = stronger influence on the AI's decision.
                    </div>
                </div>
            </div>
            
            <div style="background: white; padding: 1rem; border-radius: 8px; border: 2px solid #e5e7eb; box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);">
                <div style="margin-bottom: 0.75rem; font-weight: 600; color: #374151; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem;">
                    📱 Message Analysis:
                </div>
                <div style="color: #1f2937; line-height: 1.9; font-size: 0.95rem;">
                    ${highlightedHTML}
                </div>
            </div>
            
            <div style="margin-top: 1rem; padding: 0.75rem; background: ${isSmishing ? '#fef2f2' : '#f0fdf4'}; border-radius: 6px; border-left: 3px solid ${isSmishing ? '#ef4444' : '#10b981'};">
                <p style="margin: 0; font-size: 0.9rem; color: ${isSmishing ? '#7f1d1d' : '#065f46'};">
                    <strong>Final Verdict:</strong> The AI identified key ${isSmishing ? 'threat indicators' : 'legitimate patterns'} and classified this as <strong style="text-transform: uppercase;">${actualPrediction}</strong>
                </p>
            </div>
        </div>
    `;
}


// Action Buttons Functions
function showActionButtons() {
    const actionButtonsSection = document.getElementById('actionButtonsSection');
    if (actionButtonsSection) {
        actionButtonsSection.classList.remove('hidden');
        
    }
}

function selectAction(actionKey) {
    selectedAction = actionKey;
    
    // Update button states
    const allButtons = document.querySelectorAll('.action-btn');
    allButtons.forEach(btn => {
        btn.classList.remove('active');
    });
    
    const selectedButton = document.querySelector(`[onclick="selectAction('${actionKey}')"]`);
    if (selectedButton) {
        selectedButton.classList.add('active');
    }
    
    // Display guidelines
    displayGuidelines(actionKey);
}

function displayGuidelines(actionKey) {
    const guidelinesSection = document.getElementById('guidelinesSection');
    const guidelineContent = document.getElementById('guidelineContent');
    
    if (!guidelinesSection || !guidelineContent) return;
    
    const guideline = actionGuidelines[actionKey];
    
    if (!guideline) return;
    
    guidelineContent.innerHTML = `
        <div class="guideline-header" style="background: ${guideline.color};">
            <h3>${guideline.title}</h3>
        </div>
        
        <div class="guideline-body">
            <div class="guideline-section immediate-actions">
                <h4>⚡ Immediate Actions</h4>
                <ul>
                    ${guideline.immediate.map(action => `<li>${action}</li>`).join('')}
                </ul>
            </div>
            
            <div class="guideline-section prevention-tips">
                <h4>🛡️ Prevention Tips</h4>
                <ul>
                    ${guideline.prevention.map(tip => `<li>${tip}</li>`).join('')}
                </ul>
            </div>
            
        </div>
    `;
    
    guidelinesSection.classList.remove('hidden');
    
    // Scroll to guidelines
    setTimeout(() => {
        guidelinesSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
}

// Initialize page-specific functionality
document.addEventListener('DOMContentLoaded', function() {
    // Add enter key support for message input on analysis page
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && e.ctrlKey) {
                analyzeMessageML();
            }
        });
    }
});

