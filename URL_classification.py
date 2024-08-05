import requests
import feedparser
class URLClassifier:
    def __init__(self, url):
        self.url = url
    def is_valid_url(self):
        return self.url.lower().startswith('https://')
    def check_status_code(self):
        try:
            response = requests.get(self.url, timeout=10)
            if response.status_code == 200:
                return response
            else:
                print(f"{self.url} returned a non-200 status code: {response.status_code}")
                return None
        except requests.RequestException as e:
            print(f"Error accessing {self.url}: {e}")
            return None
    def is_xml_feed(self, response):
        content_type = response.headers.get('Content-Type', '')
        if 'xml' in content_type or 'rss' in content_type:
            return True
        else:
            feed = feedparser.parse(response.content)
            return feed.bozo == 0

    def classify_url(self):
        if not self.is_valid_url():
            print(f"{self.url} is not a valid HTTPS URL.")
            return
        response = self.check_status_code()
        if response:
            if self.is_xml_feed(response):
                print(f"{self.url} is identified as an XML feed.")
            else:
                print(f"{self.url} is not a valid feed.")
url = 'https://auscert.org.au/rss/bulletins/'  
classifier = URLClassifier(url)
classifier.classify_url()
