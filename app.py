import streamlit as st
import pickle
import pandas as pd
import numpy as np
import joblib
import tldextract
import ipaddress
from urllib.parse import urlparse

model = joblib.load('models/cart_tuned.pkl')

def urllen(url):
    return len(url)

def dotcount(url):
    return url.count('.')

def delimitercount(url):
    return url.count(';') + url.count('_') + url.count('?') + url.count('=') + url.count('&')

def ipcheck(url):
    try:
        if ipaddress.ip_address(url):
            return 1
    except:
        return 0

def hyphencount(url):
    return url.count('-')

def atcount(url):
    return url.count('@')

def subdircount(url):
    return url.count('/')

def subdomaincount(subdomain):
    if subdomain:
        return len(subdomain.split('.'))
    else:
        return 0

def querycount(query):
    if query:
        return len(query.split('&'))
    else:
        return 0

def preprocess(df):
	for i in range(len(df)):
		url = str(df.loc[i, "URL"])
		ext = tldextract.extract(url)
		path = urlparse(url)

		df.loc[i, "urllen"] = urllen(url)
		df.loc[i, "dotcount"] = dotcount(ext.subdomain)
		df.loc[i, "delimitercount"] = delimitercount(url)
		df.loc[i, "ipcheck"] = ipcheck(ext.domain)
		df.loc[i, "hyphencount"] = hyphencount(path.netloc)
		df.loc[i, "atcount"] = atcount(path.netloc)
		df.loc[i, "subdircount"] = subdircount(path.path)
		df.loc[i, "subdomaincount"] = subdomaincount(ext.subdomain)
		df.loc[i, "querycount"] = querycount(path.query)

	return df

def predict(model, sentence):
	columns = ["URL", "urllen", "dotcount", "delimitercount", "ipcheck", "hyphencount", "atcount", "subdircount", "subdomaincount", "querycount"]
	df = pd.DataFrame(columns = columns)
	df.loc[0, "URL"] = str(sentence)
	df['URL'] = df['URL'].str.replace(r'https://', '')
	df['URL'] = df['URL'].str.replace(r'http://', '')
	output = preprocess(df)
	df.drop(columns=["URL"], inplace=True)
	output = model.predict(output)
	result = output.item()

	categories = {
		0: "NORMAL",
		1: "PHISHING",
	}

	return st.success("THIS URL IS: " + categories.get(result))

st.title("USOM PHISHING URL DETECTION")
text = st.text_input('...')
res = st.button('PREDICT')

if res:
	predict(model, text)
