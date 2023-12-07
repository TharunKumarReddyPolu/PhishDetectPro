function detectPhishing(url, classname) {
    // Send request to machine learning API with the URL as the input
    fetch(`http://54.174.215.145/api?url=${url}`, {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
        },
    })
        .then((response) => response.json())
        .then((data) => {
            console.log(data);
            let test = data[0];
            console.log(test);
            console.log(typeof test);
            var resultDiv = document.getElementsByClassName(classname)[0];
            if (typeof test === "string") {
                resultDiv.innerHTML = test;
            } else {
                resultDiv.innerHTML = data.msg;
            }
        })
        .catch((error) => {
            console.error("Error:", error);
        });
}

document.addEventListener("DOMContentLoaded", function () {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        var url = tabs[0].url;
        document.getElementById("url-input").value = url;
        detectPhishing(url, "check");
    });

    document
        .getElementById("url-form")
        .addEventListener("submit", function (event) {
            event.preventDefault();
            var url = document.getElementById("url-input1").value;
            detectPhishing(url, "result");
        });
});