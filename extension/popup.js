document.addEventListener("DOMContentLoaded", function () {
    const authButton = document.getElementById("authButton");
    const checkEmailButton = document.getElementById("checkEmail");
    authButton.addEventListener("click", authenticate);
    checkEmailButton.addEventListener("click", checkEmail);
});
pollAuthenticationStatus();
function authenticate() {
    showResult("⏳ Initiating authentication...", "blue");
    fetch("http://127.0.0.1:5000/start_auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
    })
    .then(response => response.json())
    .then(data => {
        if (data.auth_url) {
            chrome.tabs.create({ url: data.auth_url, active: true });
        } else {
            showResult("❌ Failed to start authentication.", "red");
        }
    })
    .catch(error => {
        console.error("Error during authentication:", error);
        showResult("❌ Error initiating authentication.", "red");
    });
}

function pollAuthenticationStatus() {
    const interval = setInterval(() => {
        fetch("http://127.0.0.1:5000/auth_status")
        .then(response => response.json())
        .then(data => {
            if (data.status === "authenticated") {
                clearInterval(interval);
                authentication("✅ Authentication successful!", "green", data.user);
                document.getElementById("checkEmail").disabled = false;
                document.getElementById("authButton").disabled = true;
            } else if (data.status === "failed") {
                clearInterval(interval);
                authentication("❌ Authentication failed!", "red");
            }else if(data.status === "pending"){
                clearInterval(interval);
                authentication("⏳ Authentication pending...", "blue");
            }
        })
        .catch(error => {
            console.error("Polling error:", error);
            clearInterval(interval);
            showResult("❌ Error during authentication.", "red");
        });
    }, 2000);
}

function checkEmail() {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        let activeTab = tabs[0];
        if (activeTab.url.includes("mail.google.com")) {
            chrome.scripting.executeScript(
                {
                    target: { tabId: activeTab.id },
                    function: extractEmailData
                },
                (results) => {
                    if (results && results[0] && results[0].result) {
                        const { links, messageId } = results[0].result;
                        sendToBackend(links, messageId);
                    } else {
                        showResult("⚠️ Could not extract email data.", "orange");
                    }
                }
            );
        } else {
            showResult("❌ Open an email in Gmail first!", "red");
        }
    });
}

function extractEmailData() {
    let emailBody = document.querySelector(".a3s.aiL");
    let links = Array.from(emailBody.querySelectorAll("a")).map(a => a.href);
    const urlParams = new URLSearchParams(window.location.search);
    const messageId = urlParams.get('messageid') || 
                      document.querySelector('[data-legacy-message-id]')?.dataset.legacyMessageId;
    return { links, messageId };
}

function sendToBackend(links, messageId) {
    fetch("http://127.0.0.1:5000/check_email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ links, message_id: messageId })
    })
    .then(response => response.json())
    .then(data => {
        let message = data.is_phishing ? "🚨 Phishing Detected!" : "✅ This email is safe!";
        let color = data.is_phishing ? "red" : "green";

        // Display phishing and non-phishing probabilities
        let probabilities = `Phishing Probability: ${data.phis_pro}% | Non-Phishing Probability: ${data.non_phis_pro}%`;

        // Update the result display
        showResult(`${message}\n${probabilities}`, color);
    })
    .catch(error => {
        console.error("Error:", error);
        showResult("❌ Error connecting to server.", "red");
    });
}

function authentication(message, color, user = null) {
    let resultDiv = document.getElementById("status");
    if (user) {
        resultDiv.innerText = `${message} User: ${user}`;
    } else {
        resultDiv.innerText = message;
    }
    resultDiv.style.color = color;
}

function showResult(message, color) {
    let resultDiv = document.getElementById("result");
    resultDiv.innerText = message;
    resultDiv.style.color = color;
}