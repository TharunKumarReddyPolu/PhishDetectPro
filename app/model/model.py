import pickle
from pathlib import Path
import numpy as np
from app.model.Feature_Extraction import FeatureExtraction

_version_ = "0.1.0"

BASE_DIR = Path(__file__).resolve(strict=True).parent

class ClassifyURL(FeatureExtraction):
    
    # This class inherits FeatureExtraction class to access all its methods
    # The main classification of the URL is performed using the methods of this class
    
    def __init__(self):
        pass
    
    def predict(self,url):
        featureExtract = FeatureExtraction(url)
        features = featureExtract.getFeaturesList()

        return self.classify(np.array(features).reshape((1,-1)))

        
    def classify(self,features): 
        # Load the pickle file
        with open(f"{BASE_DIR}/phish_classifier.pkl", 'rb') as file:
            pickled_model = pickle.load(file)
    
        # Classify the URL features using the loaded pickle file
        result = pickled_model.predict(features)
        if result == -1:
            return "Website seems legitimate, Good to Proceed..."
        else:
            return "Website seems phishing, Beware..."