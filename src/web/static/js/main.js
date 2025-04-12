/**
 * AI_MAL Web Interface - Main JavaScript
 * 
 * This file handles the client-side functionality for the AI_MAL web interface,
 * including real-time updates via Socket.IO and user interactions.
 */

// Initialize Socket.IO connection
let socket;

// Connect to Socket.IO when document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Connect to Socket.IO server
    socket = io();
    
    // Socket connection event handlers
    socket.on('connect', function() {
        console.log('Connected to server');
        updateConnectionStatus(true);
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        updateConnectionStatus(false);
    });
    
    socket.on('scan_update', function(data) {
        console.log('Received scan update:', data);
        updateScanProgress(data);
    });
    
    // Check for scan status element
    const scanProgressElement = document.getElementById('scan-progress');
    if (scanProgressElement) {
        // Extract scan ID from the page
        const scanId = scanProgressElement.dataset.scanId;
        if (scanId) {
            // Request initial status
            socket.emit('request_status', { scan_id: scanId });
            
            // Set up periodic status requests
            setInterval(function() {
                socket.emit('request_status', { scan_id: scanId });
            }, 5000);
        }
    }
    
    // Set up event handlers for UI elements
    setupEventHandlers();
});

/**
 * Update the connection status indicator
 * @param {boolean} connected - Whether the client is connected to the server
 */
function updateConnectionStatus(connected) {
    const statusElement = document.getElementById('connection-status');
    if (statusElement) {
        if (connected) {
            statusElement.innerHTML = '<span class="badge bg-success">Connected</span>';
        } else {
            statusElement.innerHTML = '<span class="badge bg-danger">Disconnected</span>';
        }
    }
}

/**
 * Update scan progress based on received data
 * @param {Object} data - Scan update data from server
 */
function updateScanProgress(data) {
    const progressBar = document.getElementById('scan-progress-bar');
    const progressText = document.getElementById('scan-progress-text');
    const statusElement = document.getElementById('scan-status');
    
    if (progressBar && data.progress !== undefined) {
        progressBar.style.width = data.progress + '%';
        progressBar.setAttribute('aria-valuenow', data.progress);
        
        // Update progress bar color based on status
        if (data.progress === 100) {
            progressBar.classList.remove('bg-primary', 'bg-danger');
            progressBar.classList.add('bg-success');
        } else if (data.message && data.message.toLowerCase().includes('error')) {
            progressBar.classList.remove('bg-primary', 'bg-success');
            progressBar.classList.add('bg-danger');
        } else {
            progressBar.classList.remove('bg-danger', 'bg-success');
            progressBar.classList.add('bg-primary');
        }
    }
    
    if (progressText && data.message) {
        progressText.textContent = data.message;
    }
    
    if (statusElement && data.progress === 100) {
        // Check if there was an error
        if (data.message && data.message.toLowerCase().includes('error')) {
            statusElement.innerHTML = '<span class="badge bg-danger">Error</span>';
        } else {
            statusElement.innerHTML = '<span class="badge bg-success">Completed</span>';
            // Show results button if scan completed successfully
            const resultsButton = document.getElementById('view-results-button');
            if (resultsButton) {
                resultsButton.classList.remove('d-none');
            }
        }
    }
    
    // Update log output if available
    updateLogOutput(data);
    
    // If scan is complete, reload part of the page to show results
    if (data.progress === 100 && !data.message.toLowerCase().includes('error')) {
        // Wait a moment before reloading to ensure server has processed everything
        setTimeout(function() {
            const resultsContainer = document.getElementById('scan-results-container');
            if (resultsContainer) {
                loadScanResults(data.scan_id);
            }
        }, 2000);
    }
}

/**
 * Update the log output area with new messages
 * @param {Object} data - Scan update data from server
 */
function updateLogOutput(data) {
    const logOutput = document.getElementById('log-output');
    if (logOutput && data.message) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        
        // Add appropriate class based on message content
        if (data.message.toLowerCase().includes('error')) {
            logEntry.classList.add('text-danger');
        } else if (data.message.toLowerCase().includes('warning')) {
            logEntry.classList.add('text-warning');
        } else if (data.message.toLowerCase().includes('complete')) {
            logEntry.classList.add('text-success');
        }
        
        logEntry.innerHTML = `<span class="log-time">[${timestamp}]</span> ${data.message}`;
        logOutput.appendChild(logEntry);
        
        // Auto-scroll to bottom
        logOutput.scrollTop = logOutput.scrollHeight;
    }
}

/**
 * Load scan results via AJAX
 * @param {string} scanId - The ID of the scan
 */
function loadScanResults(scanId) {
    const resultsContainer = document.getElementById('scan-results-container');
    if (resultsContainer) {
        resultsContainer.innerHTML = '<div class="text-center p-3"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div><p class="mt-2">Loading results...</p></div>';
        
        fetch(`/api/scan/results/${scanId}`)
            .then(response => response.json())
            .then(data => {
                // Process and display results
                displayScanResults(data, resultsContainer);
            })
            .catch(error => {
                console.error('Error loading results:', error);
                resultsContainer.innerHTML = `<div class="alert alert-danger">Error loading results: ${error.message}</div>`;
            });
    }
}

/**
 * Display scan results in the container
 * @param {Object} data - The scan results data
 * @param {Element} container - The container element to display results in
 */
function displayScanResults(data, container) {
    if (!data.hosts || Object.keys(data.hosts).length === 0) {
        container.innerHTML = '<div class="alert alert-info">No hosts were discovered in this scan.</div>';
        return;
    }
    
    let html = '<div class="mt-4">';
    
    // Hosts section
    html += '<h4><i class="fas fa-network-wired me-2"></i> Discovered Hosts</h4>';
    html += '<div class="table-responsive">';
    html += '<table class="table table-striped table-hover">';
    html += '<thead><tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Open Ports</th></tr></thead>';
    html += '<tbody>';
    
    for (const ip in data.hosts) {
        const host = data.hosts[ip];
        html += `<tr>
            <td>${ip}</td>
            <td>${host.hostname || 'N/A'}</td>
            <td>${host.os || 'Unknown'}</td>
            <td>${host.open_ports ? host.open_ports.join(', ') : 'None detected'}</td>
        </tr>`;
    }
    
    html += '</tbody></table></div>';
    
    // Vulnerabilities section if available
    if (data.vulnerabilities && Object.keys(data.vulnerabilities).length > 0) {
        html += '<h4 class="mt-4"><i class="fas fa-bug me-2"></i> Vulnerabilities</h4>';
        html += '<div class="table-responsive">';
        html += '<table class="table table-striped table-hover">';
        html += '<thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Vulnerability</th><th>Severity</th></tr></thead>';
        html += '<tbody>';
        
        for (const ip in data.vulnerabilities) {
            const vulns = data.vulnerabilities[ip];
            for (const vuln of vulns) {
                let severityClass = '';
                switch ((vuln.severity || '').toLowerCase()) {
                    case 'critical':
                        severityClass = 'vuln-severity-critical';
                        break;
                    case 'high':
                        severityClass = 'vuln-severity-high';
                        break;
                    case 'medium':
                        severityClass = 'vuln-severity-medium';
                        break;
                    case 'low':
                        severityClass = 'vuln-severity-low';
                        break;
                }
                
                html += `<tr class="${severityClass}">
                    <td>${ip}</td>
                    <td>${vuln.port || 'N/A'}</td>
                    <td>${vuln.service || 'N/A'}</td>
                    <td>${vuln.name || 'Unknown'}</td>
                    <td><span class="badge ${getSeverityBadgeClass(vuln.severity)}">${vuln.severity || 'Unknown'}</span></td>
                </tr>`;
            }
        }
        
        html += '</tbody></table></div>';
    }
    
    // AI Analysis section if available
    if (data.analysis && Object.keys(data.analysis).length > 0) {
        html += '<h4 class="mt-4"><i class="fas fa-brain me-2"></i> AI Analysis</h4>';
        html += '<div class="card"><div class="card-body">';
        
        for (const key in data.analysis) {
            if (key === 'summary') {
                html += `<div class="mb-3">
                    <h5>Summary</h5>
                    <p>${data.analysis.summary}</p>
                </div>`;
            } else if (key === 'recommendations') {
                html += `<div class="mb-3">
                    <h5>Recommendations</h5>
                    <ul>`;
                for (const rec of data.analysis.recommendations) {
                    html += `<li>${rec}</li>`;
                }
                html += '</ul></div>';
            } else if (typeof data.analysis[key] === 'string') {
                html += `<div class="mb-3">
                    <h5>${key.charAt(0).toUpperCase() + key.slice(1)}</h5>
                    <p>${data.analysis[key]}</p>
                </div>`;
            }
        }
        
        html += '</div></div>';
    }
    
    html += '</div>';
    container.innerHTML = html;
}

/**
 * Get the appropriate Bootstrap badge class for a severity level
 * @param {string} severity - The severity level
 * @returns {string} - The badge class
 */
function getSeverityBadgeClass(severity) {
    switch ((severity || '').toLowerCase()) {
        case 'critical':
            return 'bg-danger';
        case 'high':
            return 'bg-warning text-dark';
        case 'medium':
            return 'bg-info text-dark';
        case 'low':
            return 'bg-success';
        default:
            return 'bg-secondary';
    }
}

/**
 * Set up event handlers for UI elements
 */
function setupEventHandlers() {
    // Toggle advanced options in the scan form
    const advancedToggle = document.getElementById('advanced-options-toggle');
    const advancedOptions = document.getElementById('advanced-options');
    
    if (advancedToggle && advancedOptions) {
        advancedToggle.addEventListener('click', function(e) {
            e.preventDefault();
            advancedOptions.classList.toggle('d-none');
            
            if (advancedOptions.classList.contains('d-none')) {
                advancedToggle.innerHTML = '<i class="fas fa-caret-down me-1"></i> Show Advanced Options';
            } else {
                advancedToggle.innerHTML = '<i class="fas fa-caret-up me-1"></i> Hide Advanced Options';
            }
        });
    }
    
    // Handle scan type selection to show relevant options
    const scanTypeSelect = document.getElementById('scan-type');
    if (scanTypeSelect) {
        scanTypeSelect.addEventListener('change', function() {
            updateScanOptions(this.value);
        });
        
        // Initialize with current value
        updateScanOptions(scanTypeSelect.value);
    }
}

/**
 * Update scan options based on selected scan type
 * @param {string} scanType - The selected scan type
 */
function updateScanOptions(scanType) {
    const vulnOptions = document.getElementById('vuln-options');
    const msfOptions = document.getElementById('msf-options');
    const aiOptions = document.getElementById('ai-options');
    
    if (vulnOptions) {
        if (scanType === 'full' || scanType === 'vuln') {
            vulnOptions.classList.remove('d-none');
        } else {
            vulnOptions.classList.add('d-none');
        }
    }
    
    if (msfOptions) {
        if (scanType === 'full' || scanType === 'exploit') {
            msfOptions.classList.remove('d-none');
        } else {
            msfOptions.classList.add('d-none');
        }
    }
    
    if (aiOptions) {
        if (scanType === 'full' || scanType === 'ai') {
            aiOptions.classList.remove('d-none');
        } else {
            aiOptions.classList.add('d-none');
        }
    }
} 