function getEmailContent() {
    let emailBody = document.querySelector(".a3s.aiL"); // Gmail email body
    let links = Array.from(emailBody.querySelectorAll("a")).map(a => a.href);
    return links;
}

function getCurrentMessageId() {
    // Get message ID from the URL or DOM
    const urlParams = new URLSearchParams(window.location.search);
    const messageId = urlParams.get('messageid') || 
                     document.querySelector('[data-legacy-message-id]')?.dataset.legacyMessageId;
    return messageId;
}

function sendToBackend(links,messageId) {
    fetch("http://127.0.0.1:5000/check_email", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ links: links,message_id: messageId })
    })
    .then(response => response.json())
    .then(data => {
        displayWarning(data);
    })
    .catch(error => console.error("Error:", error));
}

function displayWarning(data) {
    let warningBanner = document.createElement("div");
    warningBanner.style.position = "fixed";
    warningBanner.style.top = "10px";
    warningBanner.style.left = "10px";
    warningBanner.style.padding = "10px";
    warningBanner.style.backgroundColor = data.is_phishing ? "red" : "green";
    warningBanner.style.color = "white";
    warningBanner.innerText = data.is_phishing ? "🚨 Phishing Detected!" : "✅ Safe Email";
    document.body.appendChild(warningBanner);
}

// Run the script when an email is opened
setTimeout(() => {
    const messageId = getCurrentMessageId();
    let links = getEmailContent();
    if (messageId &&links.length > 0) {
        sendToBackend(messageId,links);
    }
}, 3000);