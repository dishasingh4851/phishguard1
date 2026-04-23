import ipaddress
import re
import requests
from bs4 import BeautifulSoup
import whois
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.features = []

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            self.response = None
            self.soup = BeautifulSoup("", 'html.parser')

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            self.domain = ""

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.Hppts(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.InfoEmail(),
            self.WebsiteForwarding(),
            self.AgeofDomain(),
            self.GoogleIndex()
        ]

    # 1
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2
    def longUrl(self):
        return 1 if len(self.url) < 75 else -1

    # 3
    def shortUrl(self):
        return -1 if re.search(r'bit\.ly|goo\.gl|t\.co', self.url) else 1

    # 4
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5
    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # 6 ✅ FIXED
    def prefixSuffix(self):
        return -1 if self.domain.count("-") > 2 else 1

    # 7
    def SubDomains(self):
        dots = self.domain.count(".")
        return 1 if dots <= 2 else -1

    # 8
    def Hppts(self):
        return 1 if self.urlparse.scheme == "https" else -1

    # 9 ✅ FIXED
    def DomainRegLen(self):
        try:
            exp = self.whois_response.expiration_date
            cre = self.whois_response.creation_date

            if isinstance(exp, list): exp = exp[0]
            if isinstance(cre, list): cre = cre[0]

            if not exp or not cre:
                return 0

            months = (exp.year - cre.year) * 12 + (exp.month - cre.month)
            return 1 if months >= 12 else 0
        except:
            return 0

    # 10
    def Favicon(self):
        return 1 if self.soup else -1

    # 11
    def NonStdPort(self):
        return -1 if ":" in self.domain else 1

    # 12
    def HTTPSDomainURL(self):
        return -1 if "https" in self.domain else 1

    # 13
    def InfoEmail(self):
        return -1 if "mailto" in str(self.soup) else 1

    # 14
    def WebsiteForwarding(self):
        try:
            return 1 if len(self.response.history) <= 1 else 0
        except:
            return 0

    # 15 ✅ FIXED
    def AgeofDomain(self):
        try:
            cre = self.whois_response.creation_date
            if isinstance(cre, list): cre = cre[0]

            if not cre:
                return 0

            age = (date.today().year - cre.year) * 12
            return 1 if age >= 6 else 0
        except:
            return 0

    # 16 ✅ FIXED
    def GoogleIndex(self):
        return 0  # neutral

    def getFeaturesList(self):
        return self.features