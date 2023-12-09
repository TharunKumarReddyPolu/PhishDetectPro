from fastapi import FastAPI
from pydantic import BaseModel
from app.model.model import ClassifyURL
from app.model.model import __version__ as model_version
import validators

# Create a FastAPI instance
app = FastAPI()
# Create an instance of the ClassifyURL class for URL classification
classifier = ClassifyURL()

class TextIn(BaseModel):
    text: str

class PredictionOut(BaseModel):
    SiteType: str

# Define a FastAPI route at the endpoint "/" which redirects to home
@app.get("/")
def home():
    return {"health_check": "OK", 
            "model_version": model_version}

# Define a FastAPI route at the endpoint "/api" with an HTTP GET method
@app.get("/predict")
def detectPhish(url: str=''):
    # Validate if the provided URL is valid
    if not validators.url(url):
        return {'msg': 'Invalid URL'}
    
    # Use the classifier to predict whether the URL is associated with phishing
    SiteType = classifier.predict(url)
    # Return the classification result in the response
    return {"SiteStatus": SiteType}
    # return {"ping": "Hello from PhishDetectPro!"}