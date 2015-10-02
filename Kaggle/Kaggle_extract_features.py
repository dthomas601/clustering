__author__ = 'temp'

import os
import sys
import re
sys.path.append("C:\\DeMarcus\\cuckoo_parser\\Experimental\\MalwareFeatures")
import pe_class as p
import multiprocessing
from multiprocessing import Pool
from sklearn.feature_extraction.text import HashingVectorizer
from itertools import repeat
import csv



def read_csv(path):
    with open(path, 'rb') as f:
        reader = csv.reader(f)
        mydict={}
        unique=set()
        for rows in reader:
            mydict[rows[0]] = rows[1]
            if str(rows[1]).isdigit():
                unique.add(rows[1])


    return mydict,sorted(unique)

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



def getVector((sample_path,dic)):

    #print parse_file(sample_path)
    return parse_file(sample_path),dic.get(os.path.basename(sample_path).split(".")[0])


if __name__ == '__main__':

    #sys.stdout = open('output_file2.txt', 'w')

    #base_path="/Volumes/malware/samples/Kaggle/train"
    base_path="Z:\\projects\\idaho-bailiff\\C4\\Labeled_Malware_Family_Dataset\\train"
    label_path="Z:\\projects\\idaho-bailiff\\C4\\Labeled_Malware_Family_Dataset\\trainLabels.csv"
    #base_path="/Volumes/DISK_IMG/samples/Kaggle/train"


    labels,unique=read_csv(label_path)

    label_listing=[]
    sample_list=[]

    for s in os.listdir(base_path):
        if '.bytes' in s:
            sample_list.append(os.path.join(base_path,s))

    blist=[]
    pool=Pool(maxtasksperchild=25,processes=multiprocessing.cpu_count()-2)
    #for results in pool.imap(getVector,sample_list):
    for results in pool.imap(getVector,zip(sample_list,repeat(labels))):

        #matrix=sparse.hstack((matrix,results),format='csr')
        #print matrix.shape
        #print results[1]
        blist.append(results[0])
        label_listing.append(results[1])



    vectorizer= HashingVectorizer(analyzer=str.split,input='content',decode_error='ignore',
                                 strip_accents='ascii',ngram_range=(1,2),n_features=1048576)#,tokenizer=tokenize)

    v=vectorizer.fit_transform(blist)
    print labels
    print len(unique)
    print label_listing



