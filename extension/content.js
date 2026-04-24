chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SHOW_WARNING") {
        showPhishingWarning(message.data);
    }
});

function showPhishingWarning(data) {
    // Prevent multiple warnings
    if (document.getElementById('phishguard-warning-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-warning-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: #d93025;
        color: white;
        z-index: 9999999999;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        text-align: center;
        padding: 20px;
    `;

    overlay.innerHTML = `
        <div style="font-size: 80px; margin-bottom: 20px;">🚨</div>
        <h1 style="font-size: 40px; margin-bottom: 10px;">Deceptive Site Ahead!</h1>
        <p style="font-size: 18px; max-width: 600px; margin-bottom: 30px;">
            PhishGuard AI has detected that this website is a <strong>${data.status.toUpperCase()}</strong> threat. 
            Attackers may try to trick you into doing something dangerous like installing software or revealing your personal information (for example, passwords, phone numbers, or credit cards).
        </p>
        <p style="font-size: 14px; color: #ffeb3b; margin-bottom: 30px;">
            Reason: ${data.reason} (Risk Score: ${data.risk_score}%)
        </p>
        <div style="display: flex; gap: 20px;">
            <button id="pg-back-btn" style="padding: 15px 30px; font-size: 18px; border: none; border-radius: 5px; cursor: pointer; background: white; color: #d93025; font-weight: bold;">
                Back to Safety
            </button>
            <button id="pg-ignore-btn" style="padding: 10px 20px; font-size: 14px; border: 1px solid white; border-radius: 5px; cursor: pointer; background: transparent; color: white;">
                Ignore and Proceed (Not Recommended)
            </button>
        </div>
        <p style="margin-top: 50px; font-size: 12px; opacity: 0.8;">Protected by PhishGuard AI Hybrid Engine</p>
    `;

    document.body.appendChild(overlay);

    document.getElementById('pg-back-btn').onclick = () => {
        window.history.back();
        if (window.history.length <= 1) window.close();
    };

    document.getElementById('pg-ignore-btn').onclick = () => {
        overlay.style.display = 'none';
    };
}
