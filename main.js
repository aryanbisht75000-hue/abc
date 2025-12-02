document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('url');
    const scanButton = document.getElementById('scan-button');
    const resultsSection = document.getElementById('results');
    const loadingSection = document.getElementById('loading');
    const errorSection = document.getElementById('error-message');
    const errorText = document.getElementById('error-text');
    
    // Add event listener for scan button
    scanButton.addEventListener('click', scanUrl);
    
    // Also trigger scan when pressing Enter in the input field
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            scanUrl();
        }
    });
    
    function scanUrl() {
        const url = urlInput.value.trim();
        
        // Basic URL validation
        if (!url) {
            showError('Please enter a URL to scan');
            return;
        }
        
        // Show loading state
        resultsSection.classList.add('hidden');
        loadingSection.classList.remove('hidden');
        errorSection.classList.add('hidden');
        
        // Send request to backend
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw err; });
            }
            return response.json();
        })
        .then(data => {
            // Hide loading state
            loadingSection.classList.add('hidden');
            
            // Check for error in response
            if (data.error) {
                throw new Error(data.error);
            }
            
            // Update UI with results
            updateResults(data);
            resultsSection.classList.remove('hidden');
        })
        .catch(error => {
            console.error('Error:', error);
            loadingSection.classList.add('hidden');
            showError(error.message || 'An error occurred while scanning the URL. Please try again.');
        });
    }
    
    function updateResults(data) {
        // Update status badge
        const statusBadge = document.getElementById('status-badge');
        statusBadge.textContent = data.status;
        statusBadge.className = 'px-3 py-1 rounded-full text-sm font-medium';
        
        // Set risk level styling
        if (data.risk_level === 'high') {
            statusBadge.classList.add('bg-red-100', 'text-red-800');
        } else if (data.risk_level === 'medium') {
            statusBadge.classList.add('bg-yellow-100', 'text-yellow-800');
        } else {
            statusBadge.classList.add('bg-green-100', 'text-green-800');
        }
        
        // Update risk score
        document.getElementById('risk-score').textContent = data.risk_score;
        
        // Update URL analysis
        updateFactor('url-analysis', data.factors.url_analysis);
        
        // Update domain age
        updateFactor('domain-age', data.factors.domain_age);
        
        // Update SSL check
        updateFactor('ssl', data.factors.ssl);
        
        // Update reachability
        updateFactor('reachability', data.factors.reachability);
        
        // Update safety tips based on risk level
        updateSafetyTips(data.risk_level);
    }
    
    function updateFactor(factorId, factorData) {
        const scoreElement = document.getElementById(`${factorId}-score`);
        const detailsElement = document.getElementById(`${factorId}-details`);
        
        // Update score badge
        scoreElement.textContent = factorData.score > 0 ? `+${factorData.score}` : '0';
        scoreElement.className = 'px-2 py-1 text-xs font-medium rounded-full';
        
        if (factorData.score >= 2) {
            scoreElement.classList.add('bg-red-100', 'text-red-800');
        } else if (factorData.score === 1) {
            scoreElement.classList.add('bg-yellow-100', 'text-yellow-800');
        } else {
            scoreElement.classList.add('bg-green-100', 'text-green-800');
        }
        
        // Update details
        detailsElement.textContent = factorData.comment || 'No issues detected';
    }
    
    function updateSafetyTips(riskLevel) {
        const tipsList = document.getElementById('tips-list');
        tipsList.innerHTML = ''; // Clear existing tips
        
        let tips = [];
        
        if (riskLevel === 'high') {
            tips = [
                "⚠️ Do not enter any personal or financial information on this website.",
                "🔒 The website may be trying to steal your credentials.",
                "🔍 Check the URL carefully for misspellings or unusual characters.",
                "🚫 Do not download any files from this website.",
                "🛡️ Consider using a password manager to avoid entering passwords on suspicious sites."
            ];
        } else if (riskLevel === 'medium') {
            tips = [
                "⚠️ Be cautious when entering sensitive information on this website.",
                "🔍 Double-check the website's security indicators (HTTPS, padlock icon).",
                "🔒 Consider using two-factor authentication for added security.",
                "🔄 Try to access the website through a known, trusted source.",
                "📱 If on mobile, ensure you're using a secure connection (not public WiFi)."
            ];
        } else {
            tips = [
                "✅ The website appears to be safe based on our analysis.",
                "🔒 Always ensure the URL in the address bar is correct before logging in.",
                "🛡️ Keep your browser and security software up to date.",
                "🔍 Look for the padlock icon in the address bar for secure connections.",
                "📧 Be cautious of emails asking you to visit this website if you didn't request them."
            ];
        }
        
        // Add tips to the list
        tips.forEach(tip => {
            const li = document.createElement('li');
            li.className = 'flex items-start';
            li.innerHTML = `
                <span class="mr-2">${tip.split(' ')[0]}</span>
                <span>${tip.split(' ').slice(1).join(' ')}</span>
            `;
            tipsList.appendChild(li);
        });
    }
    
    function showError(message) {
        errorText.textContent = message;
        errorSection.classList.remove('hidden');
        
        // Scroll to error message
        errorSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
});
