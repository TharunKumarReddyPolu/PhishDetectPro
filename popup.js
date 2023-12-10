function detectPhishing(url) {
    var resultDiv = document.getElementById("result");
    resultDiv.innerHTML = "Checking...";

    // Send request to machine learning API with the URL as the input
    fetch(`http://127.0.0.1:8000/predict?url=${url}`, {
        method: "GET",
        mode: "no-cors",
        headers: {
            "Content-Type": "application/json",
        },
    })
        .then((response) => response.json())
        .then((data) => {
            if (typeof data === "string") {
                resultDiv.innerHTML = data;
            } else {
                resultDiv.innerHTML = data.SiteStatus;
            }
        })
        .catch((error) => {
            console.error("Error: ", error);
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