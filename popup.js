function detectPhishing(url) {
    var resultDiv = document.getElementById("result");
    resultDiv.innerHTML = "Checking...";

    // Send request to machine learning API with the URL as the input
    // Need to host our DL Model as an API
    fetch(`http://54.174.215.145/api?url=${url}`, {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
        },
    })
        .then((response) => response.json())
        .then((data) => {
            if (typeof test === "string") {
                resultDiv.innerHTML = data;
            } else {
                resultDiv.innerHTML = data.msg;
            }
        })
        .catch((error) => {
            console.error("Error:", error);
            resultDiv.innerHTML = "Error occured while checking.";
        });
}

document.addEventListener("DOMContentLoaded", function () {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        var url = tabs[0].url;
        document.getElementById("url-input").value = url;
        detectPhishing(url);
    });
});