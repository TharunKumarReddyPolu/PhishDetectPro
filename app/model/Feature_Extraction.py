import ipaddress
import re
from socket import timeout
import urllib.request
from bs4 import BeautifulSoup
import requests
import numpy as np
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    # This class contains the methods that extract the required features of the URL
    # Here, -1 indicates legitimate url and 1 indicates phishing url, 0 indicates Exception or errors.

    # features = []
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(self.url, timeout=1)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain, timeout=1)
        except:
            pass
        
        self.features.append(self.url)

        self.features.append(self.UsingIP())
        self.features.append(self.GetLength())
        self.features.append(self.TinyURL())
        self.features.append(self.HasAtSymbol())
        self.features.append(self.Redirecting())
        self.features.append(self.PrefixSuffix())
        self.features.append(self.SubDomain())
        self.features.append(self.GetDepth())
        self.features.append(self.HttpsinURL())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HttpsDomain())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.DnsRecord())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DomainRegLen())
        self.features.append(self.GoogleIndex())
        
        
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AnchorURL())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.LinksPointingToPage())
    
    # 1.Checks for IP address in URL (Using_IP)
    def UsingIP(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1
        
    # 2.Finding the length of URL and categorizing (Length)
    def GetLength(self):
        try:
            if len(self.url) < 54:
                return 1
            if len(self.url) >= 54 and len(self.url) <= 75:
                return 0
            else:
                return -1
        except:
            return 0
        
    # 3. Checking for Shortening Services in URL (Tiny_URL)
    def TinyURL(self):
        try:
            match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
            if match:
                return -1
            else:
                return 1
        except:
            return 0
        
    # 4.Checks the presence of @ in URL (At_Symbol)
    def HasAtSymbol(self):
        try:
            if re.findall("@", self.url):
                return -1
            else:
                return 1
        except:
            return 0
    
    # 5.Checking for redirection '//' in the url (Redirection)
    def Redirecting(self):
        try:
            pos = self.url.rfind('//')
            if pos > 6:
                if pos > 7:
                    return -1
                else:
                    return 1
            else:
                return 1
        except:
            return 0
        
    # 6.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
    def PrefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return 0
        
    # 7. Sub Domain of the URL (Sub_Domain)
    def SubDomain(self):
        try:
            dot_count = len(re.findall("\.", self.url))
            if dot_count == 1:
                return 1
            elif dot_count == 2:
                return 0
            else:
                return -1
        except:
            return 0
        
    # 8.Gives number of '/' in URL (URL_Depth)
    def GetDepth(self):
        try:
            s = urlparse(self.url).path.split('/')
            depth = 0
            for i in range(len(s)):
                if len(s[i]) != 0:
                    depth += 1
            return depth
        except:
            return 0

    # 9.Existence of 'HTTP' or 'HTTPS' Token in the Domain Part of the URL (Https_URL)
    def HttpsinURL(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return -1
            return 1
        except:
            return 0
    
    # 10. checking if URL uses a non-standard port in domain (NonStdPort)
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return 0

    # 11. Existence of 'HTTP' or 'HTTPS' Token in the Domain Part of the URL (Https_Domain)
    def HttpsDomain(self):
        try:
            if 'https' in self.domain:
                return 1
            return -1
        except:
            return 0
        
    # 12. Check if webpage content has email elements (Info_Email)
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup):
                return 1
            else:
                return -1
        except:
            return 0

    # 13. Check if webpage content matches WHOIS response (Abnormal_URL)
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return -1
            else:
                return 1
        except:
            return 0
        
    # 14. Check the number of redirections in webpage response history (Web_Forward)
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return -1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return 1
        except:
            return 0
    
    # 15. Checking Website traffic with Alexa database (Web_Traffic)
    def WebsiteTraffic(self):
        try:
            #Filling the whitespaces in the URL if any
            url = urllib.parse.quote(self.url)
            site_rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
                "REACH")['RANK']
            site_rank = int(site_rank)
            if site_rank <100000:
                return -1
            else:
                return 1
        except:
            return 0
    
    # 16. DNS Record availability (DNS_Record)
    def DnsRecord(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return -1
            return 1
        except:
            return 0
    
    # 17. Survival time of domain: The difference between termination time and creation time (Age_Domain)
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass
            today = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >= 6:
                return -1
            else:
                return 1
        except:
            return 0
    
    # 18. Check the age of domain using creation and expiration dates from WHOIS data (DomainRegLen)
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
            if age >=12:
                return -1
            return 1
        except:
            return 0
    
    # 19. Checking the website if it is indexed by google (Google_Index)
    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return -1
            else:
                return 1
        except:
            return 0
    
    # 20. Checks the effect of mouse over on status bar (Status_Bar_Cust)
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return -1
            else:
                return 1
        except:
            return 0
        
    # 21. Checks the status of the right click attribute (Disable_Right_Click)
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return -1
            else:
                return 1
        except:
            return 0
    
    # 22. IFrame Redirection (Iframe_Redirect)
    def IframeRedirection(self):
        try:
            if re.findall(r"<iframe>|<frameBorder>", self.response.text):
                return -1
            else:
                return 1
        except:
            return 0
    
    # 23. Checking the safety of the anchor links in the URL (Anchor_URL)
    def AnchorURL(self):
        try:
            i, unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
            i += 1
            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return -1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return 1
            except:
                return 1
        except:
            return 0
    
    # 24. checking if there are any form actions which are empty (Server_Form_Handler)
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return -1
            else :
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return 1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return -1
        except:
            return 0
    
    # 25. Check if the webpage has alert() calls (Using_Popup_Window)
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return -1
            else:
                return 1
        except:
            return 0
    
    # 26. Check if the webpage has anchor links  to the page itself (Links_Pointing_Page)
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return -1
            elif number_of_links <= 2:
                return 0
            else:
                return 1
        except:
            return 0
    
    # getter method to return the features list
    def getFeaturesList(self):
        return self.features
        
        

    