const API_URL = "http://localhost:8000/scan-url";

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        checkUrl(tab.url, tabId);
    }
});

async function checkUrl(url, tabId) {
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const result = await response.json();

        if (result.status === 'phishing' || result.status === 'suspicious') {
            chrome.action.setBadgeText({ text: '!', tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: result.status === 'phishing' ? '#FF0000' : '#FFA500', tabId: tabId });
            
            // Trigger Automatic Warning Overlay
            chrome.tabs.sendMessage(tabId, { type: "SHOW_WARNING", data: result }).catch(err => {
                // Content script might not be ready yet, that's fine
                console.log("Waiting for content script to load...");
            });
        } else {
            chrome.action.setBadgeText({ text: '', tabId: tabId });
        }
        
        // Store result for popup
        chrome.storage.local.set({ [url]: result });

    } catch (error) {
        console.error("PhishGuard AI: Backend unreachable. Make sure python main.py is running.");
    }
}
