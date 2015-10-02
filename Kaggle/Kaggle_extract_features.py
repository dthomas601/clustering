__author__ = 'temp'

import os
import sys
import re
sys.path.append("C:\\DeMarcus\\cuckoo_parser\\Experimental\\MalwareFeatures")
import pe_class as p
import multiprocessing
from multiprocessing import Pool
from sklearn.feature_extraction.text import HashingVectorizer
from scipy import sparse


def parse_file(file):
    with open(file,'r') as f:
        line=""
        for l in f:
            line+=str(" ".join(l.split(" ")[1:])).replace("\n"," ")
        return line


def tokenize(text):
    exp=re.compile('^.{2}\s$')
    #exp=re.compile('^(..)$')

    return [tok.strip() for tok in exp.split(text)]



def getVector(sample_path):

    #print parse_file(sample_path)
    return parse_file(sample_path)


if __name__ == '__main__':

    #sys.stdout = open('output_file2.txt', 'w')

    #base_path="/Volumes/malware/samples/Kaggle/train"
    base_path="Z:\\projects\\idaho-bailiff\\C4\\Labeled_Malware_Family_Dataset\\train"
    #base_path="/Volumes/DISK_IMG/samples/Kaggle/train"


    sample_list=[]

    for s in os.listdir(base_path):
        if '.bytes' in s:
            sample_list.append(os.path.join(base_path,s))

    blist=[]
    pool=Pool(maxtasksperchild=25,processes=multiprocessing.cpu_count()-2)
    for results in pool.imap(getVector,sample_list):
        #matrix=sparse.hstack((matrix,results),format='csr')
        #print matrix.shape
        blist.append(results)

    vectorizer= HashingVectorizer(analyzer=str.split,input='content',decode_error='ignore',
                                 strip_accents='ascii',ngram_range=(1,2),n_features=1048576)#,tokenizer=tokenize)

    v=vectorizer.fit_transform(blist)



