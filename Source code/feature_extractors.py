%%writefile feature_extractors.py
import re
from urllib.parse import urlparse

def extract_all_features(url):
    hostname = urlparse(url).netloc
    path = urlparse(url).path
    url_len = len(url)
    dot_count = url.count('.')
    dash_count = url.count('-')

    f1 = [url_len, len(hostname), dot_count, dash_count, url.count('/'), url.count('@')]
    while len(f1) < 87: f1.append(0)

    f2 = [dot_count, url.count('//'), dash_count, url.count('.'), url_len]
    while len(f2) < 48: f2.append(0)

    f3 = [
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else -1,
        1 if url_len > 75 else (-1 if url_len < 54 else 0),
        1 if 'bit.ly' in url or 'tinyurl' in url else -1,   
        1 if '@' in url else -1,                            
        1 if url.count('//') > 1 else -1,                   
        1 if '-' in hostname else -1,                       
        1 if dot_count > 3 else -1,                         
        1, 1, 0, 0, 0, 0, 0, 0, 0                           
    ]

    return f1, f2, f3
