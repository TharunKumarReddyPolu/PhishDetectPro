# Phish Detect Pro

## Objective

The problem we aim to investigate is the detection of phishing websites using deep learning techniques. Phishing websites are a significant cybersecurity threat, and detecting them accurately is crucial to protect users from online fraud and identity theft. Phishing attacks continue to evolve, making it challenging to detect them using traditional methods. Deep learning offers a promising approach by allowing us to leverage patterns and features in website data to identify fraudulent websites more effectively. This project is interesting because it combines cybersecurity, machine learning, and real-world applicability to 
enhance online security.

## Data Collection

To Train our deep learning model, we need a collection of legitimate and Phishing URLs.

Phishing URLs Data Collection: We use an popular opensource site called PhishTank which provides a huge collection of phishing URLs in multiple formats like CSV, XML, JSON, PHP and which gets periodically updated. Download the data file using the link: https://www.phishtank.com/developer_info.php

Legitimate URLs Data Collection: We use an another popular site called Kaggle, from which we take a dataset which is balanced and has 50% phishing and 50% legitimate URLs. Download the data file using the link: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset and we also used the dataset using the refernce paper P. Mowar and M. Jain, "Fishing out the Phishing Websites," 2021 International Conference on Cyber Situational Awareness, Data Analytics and Assessment (CyberSA), 2021, pp. 1-6, doi: 10.1109/CyberSA52016.2021.9478237. Download the data file using the link: https://zenodo.org/records/5807622#.Ycsbzy0RpQJ

## Feature Enginnering

We extracted few of the domain based features, address bar features, HTML & Javascript based features for the URLs in the datasets. This data is further split for training and testing.

Based on the document, 'Phishing Website Features.docx' in this repository, the values of each feature were converted to -1 for legitimate site and 1 for phishing site. The respective feature extraction process are in 'Feature_Extraction.py' file of this repository.

This new dataset is available in 'url_features.csv' of this repository

To understand the relationships and the correlation of the data, We have implemented the visualisations using sklearn and matplotlib libraries in Python. These visualisations are available in 'Phishing Website Detection Deep Learning.ipynb' file of this repository.

## Model Development

The Deep Learning algorithms used for this analysis are

- Support Vector Machines
- Multilayer Perceptrons
- Auto encoder Neural Network
- Convolutional Neural Network (CNN)
- Recurrent Neural Network (RNN)

These models were trained and tested on the feature extracted dataset and evaluations were done to identify the model with high performance. Out of the above methods, Multi Layer Perceptrons(MLP) algorithm had a good accuracy and fast testing time compared to the other algorithms.

The entire model training and analysis code for this project is available in 'Phishing Website Detection Deep Learning.ipynb' file of this repository.

## Results

After making adjustments and improvements, we settled on using a Multilayer Perceptrons classifier as the final model, achieving an impressive accuracy of 99.2%. This finalized model has been saved using Python's pickle module and is accessible as 'phish_classifier.pkl' within this repository.

## Future Work

Looking ahead, there are exciting possibilities for the saved model. It could be further developed into a browser extension or integrated as a plugin with internet security providers. This enhancement would enable the model to proactively alert users, helping them steer clear of potentially harmful phishing sites by accurately identifying them.

## Required Installations
### Softwares:

Python 3 and above, Docker, Heroku CLI

### Python packages: 

sklearn, numpy, pandas, pickle, matplotlib, python-whois, tensorflow, BeautifulSoup4, googlesearch
