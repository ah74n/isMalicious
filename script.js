// --- Search Bar Clear Button Logic ---
const urlInput = document.getElementById('url-input');
const clearBtn = document.getElementById('clear-btn');

// Show the 'X' only when there is text
urlInput.addEventListener('input', function() {
    if (this.value.length > 0) {
        clearBtn.style.display = 'block';
    } else {
        clearBtn.style.display = 'none';
    }
});

// Clear the input and hide the 'X' when clicked
function clearInput() {
    urlInput.value = '';
    clearBtn.style.display = 'none';
    urlInput.focus(); // Keep the cursor in the box
}
// ------------------------------------
function openTab(evt, tabName) {
    const tabContents = document.getElementsByClassName("tab-content");
    for (let i = 0; i < tabContents.length; i++) {
        tabContents[i].classList.remove("active");
    }
    const tabButtons = document.getElementsByClassName("tab-btn");
    for (let i = 0; i < tabButtons.length; i++) {
        tabButtons[i].classList.remove("active");
    }
    document.getElementById(tabName).classList.add("active");
    evt.currentTarget.classList.add("active");
    document.getElementById('results-dashboard').classList.add('hidden');
}
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
dropzone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
    if (fileInput.files.length > 0) {
        const fileName = fileInput.files[0].name;
        dropzone.querySelector('p').innerHTML = `Selected: <strong>${fileName}</strong>`;
        dropzone.style.borderColor = 'var(--teal-accent)';
    }
});
dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
});
dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
});
dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    fileInput.files = e.dataTransfer.files;
    const event = new Event('change');
    fileInput.dispatchEvent(event);
});
async function simulateScan(type) {
    const dashboard = document.getElementById('results-dashboard');
    const loader = document.getElementById('scan-loader');
    const icon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const scoreBox = document.getElementById('risk-score');
    const logBox = document.getElementById('details-log');
    const logList = document.getElementById('log-list');
    if (type === 'file') {
        alert("File scanning AI is coming next! Let's test the URL scanner first.");
        return;
    }
    const urlInput = document.getElementById('url-input').value;
    if (!urlInput) {
        alert("Please paste a URL first!");
        return;
    }
    dashboard.classList.remove('hidden');
    loader.classList.remove('hidden');
    icon.classList.add('hidden');
    scoreBox.classList.add('hidden');
    logBox.classList.add('hidden');
    statusText.innerText = "AI is Analysing...";
    statusText.className = "status-text";
    logList.innerHTML = "";
    try {
        const response = await fetch('http://127.0.0.1:5000/api/scan-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        loader.classList.add('hidden');
        icon.classList.remove('hidden');
        scoreBox.classList.remove('hidden');
        logBox.classList.remove('hidden');
        if (response.ok) {
            displayResult(data.status, data.risk_score, data.logs);
            runDynamicSandbox(urlInput);
        } else {
            statusText.innerText = "Error: " + data.error;
        }
    } catch (error) {
        console.error("Connection Error:", error);
        loader.classList.add('hidden');
        statusText.innerText = "Could not connect to Python server!";
        statusText.className = "status-text text-malicious";
    }
}
async function runDynamicSandbox(urlInput) {
    const sandboxBox = document.getElementById('sandbox-results');
    const sandboxLoader = document.getElementById('sandbox-loader');
    const sandboxContent = document.getElementById('sandbox-content');
    const screenshotImg = document.getElementById('sandbox-screenshot');
    const trafficList = document.getElementById('sandbox-traffic-list');
    sandboxBox.classList.remove('hidden');
    sandboxLoader.classList.remove('hidden');
    sandboxContent.classList.add('hidden');
    trafficList.innerHTML = "";
    try {
        const response = await fetch('http://127.0.0.1:5000/api/sandbox-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        sandboxLoader.classList.add('hidden');
        if (data.success) {
            sandboxContent.classList.remove('hidden');
            screenshotImg.src = data.screenshot;
            if (data.external_connections.length > 0) {
                data.external_connections.forEach(domain => {
                    const li = document.createElement('li');
                    li.innerText = domain;
                    trafficList.appendChild(li);
                });
            } else {
                trafficList.innerHTML = "<li style='color: green;'>No suspicious background traffic detected.</li>";
            }
        } else {
            sandboxContent.classList.remove('hidden');
            sandboxContent.innerHTML = `<p style="color: red;"><i class="fas fa-exclamation-circle"></i> Sandbox failed: ${data.error}</p>`;
        }
    } catch (error) {
        sandboxLoader.classList.add('hidden');
        console.error("Sandbox Error:", error);
    }
}
function displayResult(status, score, logs) {
    const icon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const scoreVal = document.getElementById('score-val');
    const logList = document.getElementById('log-list');
    scoreVal.innerText = score;
    if (status === 'safe') {
        icon.innerHTML = '<i class="fas fa-shield-check text-safe"></i>';
        statusText.innerText = "Likely Safe";
        statusText.className = 'status-text text-safe';
    } else if (status === 'suspicious') {
        icon.innerHTML = '<i class="fas fa-exclamation-triangle text-suspicious"></i>';
        statusText.innerText = "Suspicious Activity";
        statusText.className = 'status-text text-suspicious';
    } else {
        icon.innerHTML = '<i class="fas fa-skull-crossbones text-malicious"></i>';
        statusText.innerText = "Malicious Detected";
        statusText.className = 'status-text text-malicious';
    }
    logs.forEach(log => {
        const li = document.createElement('li');
        let bulletIcon = '<i class="fas fa-info-circle" style="color: #3498db;"></i>';
        if (log.includes("ACTIVE")) bulletIcon = '<i class="fas fa-globe" style="color: #2ecc71;"></i>';
        if (log.includes("DEAD") || log.includes("suspicious") || log.includes("abnormally")) bulletIcon = '<i class="fas fa-search-location" style="color: #e74c3c;"></i>';
        li.innerHTML = `${bulletIcon} ${log}`;
        li.style.marginBottom = "10px";
        logList.appendChild(li);
    });
}