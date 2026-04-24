chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;
    document.getElementById('url-text').innerText = url.substring(0, 50) + "...";

    chrome.storage.local.get([url], (result) => {
        if (result[url]) {
            updateUI(result[url]);
        } else {
            document.getElementById('status-text').innerText = "Analyzing...";
        }
    });
});

function updateUI(data) {
    const card = document.getElementById('status-card');
    const statusText = document.getElementById('status-text');
    const confidenceText = document.getElementById('confidence-text');
    const reasonText = document.getElementById('reason-text');

    statusText.innerText = data.status.toUpperCase();
    confidenceText.innerText = `Risk Score: ${data.risk_score}%`;
    reasonText.innerText = data.reason;

    card.className = `status-box ${data.status.toLowerCase()}`;
}
