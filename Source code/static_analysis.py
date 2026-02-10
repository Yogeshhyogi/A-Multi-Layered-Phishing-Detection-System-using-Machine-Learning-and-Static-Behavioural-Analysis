%%writefile static_analysis.py
import requests
from bs4 import BeautifulSoup
import re

def detect_framework(soup, text):
    content = text.lower()
    if "wp-content" in content or "wp-includes" in content:
        return "WordPress"
    if "react" in content or 'id="root"' in content:
        return "React.js"
    if "flutter" in content or "flutter_bootstrap.js" in content:
        return "Flutter Web"
    if "bootstrap" in content:
        return "Bootstrap"
    return "Custom / Static"

def fetch_live_behavior(url):
    data = {'iframe': 0, 'mailto': 0, 'framework': 'Unknown'}
    try:
        res = requests.get(url, timeout=4, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(res.text, "html.parser")
        
        if soup.find(["iframe", "frame"]): data['iframe'] = 1
        if soup.find("form", action=re.compile(r"mailto:")): data['mailto'] = 1
        
        data['framework'] = detect_framework(soup, res.text)
    except: 
        pass
    return data
