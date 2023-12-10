import pickle
from pathlib import Path
import numpy as np
from app.model.Feature_Extraction import FeatureExtraction

__version__ = "0.1.0"

BASE_DIR = Path(__file__).resolve(strict=True).parent

class ClassifyURL(FeatureExtraction):
    def __init__(self):
        pass
    
    def predict(self, url):
        with open(f"{BASE_DIR}/phish_classifier.pkl", 'rb') as file:
            pickled_model = pickle.load(file)
        
        result = pickled_model.predict(url)
        if result == 0:
            return "Website seems legitimate, Good to Proceed..."
        else:
            return "Website seems phishing, Beware..."