from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import validators
from Feature_Extraction import ClassifyURL

# Create a FastAPI instance
app = FastAPI()
# Create an instance of the ClassifyURL class for URL classification
classifier = ClassifyURL()

# Configure Cross-Origin Resource Sharing (CORS) middleware
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define a FastAPI route at the endpoint "/api" with an HTTP GET method
@app.get("/api")
def detectPhish(url: str=""):
    # Validate if the provided URL is valid
    if not validators.url(url):
        return {'msg': 'Invalid URL'}
    
    # Use the classifier to predict whether the URL is associated with phishing
    result = classifier.predict(url)
    # Return the classification result in the response
    return {result}