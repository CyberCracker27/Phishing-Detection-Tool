import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse


class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception as e:
            print(f"Error fetching URL: {e}")

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            print(f"Error parsing URL: {e}")

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception as e:
            print(f"Error fetching WHOIS data: {e}")

        # Extract features
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. Using IP
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except ValueError:
            return 1

    # 2. Long URL
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif 54 <= len(self.url) <= 75:
            return 0
        return -1

    # 3. Short URL
    def shortUrl(self):
        match = re.search(r'bit\.ly|goo\.gl|tinyurl|t\.co|is\.gd|ow\.ly', self.url)
        return -1 if match else 1

    # 4. Symbol @
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting //
    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # 6. Prefix-Suffix
    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    # 7. Subdomains
    def SubDomains(self):
        dot_count = self.domain.count('.')
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS
    def Https(self):
        return 1 if self.urlparse.scheme == 'https' else -1

    # 9. Domain Registration Length
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.domain in link['href']:
                    return 1
            return -1
        except:
            return -1

    # 11. Non-Standard Port
    def NonStdPort(self):
        return -1 if ':' in self.domain else 1

    # 12. HTTPS in Domain URL
    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    # 13. Request URL
    def RequestURL(self):
        try:
            total, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.domain in element['src']:
                        success += 1
            percentage = (success / total) * 100 if total > 0 else 0
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            return -1
        except:
            return -1

    # 14. Anchor URL
    def AnchorURL(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                total += 1
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower():
                    unsafe += 1
            percentage = (unsafe / total) * 100 if total > 0 else 0
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            return -1
        except:
            return -1

    # 15. Links in Script Tags
    def LinksInScriptTags(self):
        try:
            total, success = 0, 0
            for tag in ['link', 'script']:
                for element in self.soup.find_all(tag, href=True):
                    total += 1
                    if self.domain in element['href']:
                        success += 1
            percentage = (success / total) * 100 if total > 0 else 0
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            return -1
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True)) == 0:
                return 1
            else:
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            return 1 if age >= 6 else -1
        except:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            return 1 if age >= 6 else -1
        except:
            return -1

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
            if int(rank) < 100000:
                return 1
            return 0
        except:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
            if 0 < global_rank < 100000:
                return 1
            return -1
        except:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
                r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(
                r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match or ip_match:
                return -1
            return 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features