import pickle
from pathlib import Path
import numpy as np
from app.model.Feature_Extraction import FeatureExtraction
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer

_version_ = "0.1.0"

BASE_DIR = Path(__file__).resolve(strict=True).parent

class ClassifyURL(FeatureExtraction):
    def _init_(self):
        pass
    
    def predict(self, url):
        print(url)
        with open(f"{BASE_DIR}/phish_classifier.pkl", 'rb') as file:
            pickled_model = pickle.load(file)

        # Assuming 'url' is the feature and 'label' is the target variable
        tokenizer = Tokenizer(num_words=5000, oov_token="OOV")
        tokenizer.fit_on_texts(str(url))

        # Preprocessing the URL
        random_url_sequence = tokenizer.texts_to_sequences([str(url)])
        random_url_padded = pad_sequences(random_url_sequence, padding='post', maxlen=100)

        # Reshape for the CNN model
        random_url_padded_reshaped = np.reshape(random_url_padded, 
                                                (random_url_padded.shape[0], random_url_padded.shape[1], 1))

        result = pickled_model.predict(random_url_padded_reshaped)
        if result == 0:
            return "Website seems legitimate, Good to Proceed..."
        else:
            return "Website seems phishing, Beware..."