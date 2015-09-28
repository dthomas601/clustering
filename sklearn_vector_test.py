__author__ = 'dmt101'


import logging

from sklearn.datasets import fetch_20newsgroups,fetch_20newsgroups_vectorized
categories=None

# Display progress logs on stdout
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

data=fetch_20newsgroups_vectorized(subset='all')

