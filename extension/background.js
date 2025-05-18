chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    fetch("http://127.0.0.1:5000/check_email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request)
    })
    .then(response => response.json())
    .then(data => {
        chrome.runtime.sendMessage({ result: data });
    })
    .catch(error => console.error("Error:", error));
});
