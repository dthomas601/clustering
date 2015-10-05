__author__ = 'dmt101'

import os
import re
import csv
import sys
import time

from itertools import repeat

from multiprocessing import Pool

from sklearn import metrics
from sklearn.cluster import KMeans, MiniBatchKMeans
from sklearn.feature_extraction.text import HashingVectorizer, CountVectorizer



def findString(file):
    found=""
    with open (file) as f:
        print file
        for line in f:
            if "Segment type: Pure code" in line:
                #found=1
                found=line.split(":")[0]
                break

    return found

#'(^\.[a-z]{4}\:\w{8}\s\w{2}\s)$'
def getOpcodes((file,dic)):
    opcodes=""
    with open (file) as f:
        for line in f:
            if re.match(".text:\w{8}\s\w{2}\s.*\t\t",line):
                opcodes+=line.replace("\n","").replace("\t","").split(" ")[1]+" "

    if len(opcodes):
        return opcodes,dic.get(os.path.basename(file).split(".")[0])
    else:
        return None




def hash_vector_func_word(l):
    vectorizer= HashingVectorizer(non_negative=True, stop_words='english' ,input='content',decode_error='ignore',
                                 strip_accents='ascii',n_features=262144,ngram_range=(1,4))

    #return str(l).split(" ")[0],vectorizer.fit_transform(str(l).replace(str(l).split(" ")[0],""))
    return vectorizer.fit_transform(l)


def count_vector_func_word(l):
    vectorizer= CountVectorizer(input='content',decode_error='ignore',
                                 strip_accents='ascii',max_features=1000,ngram_range=(1,4))

    #return str(l).split(" ")[0],vectorizer.fit_transform(str(l).replace(str(l).split(" ")[0],""))
    return vectorizer.fit_transform(l)


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


if __name__ == '__main__':

    #sys.stdout = open('output_file2.txt', 'w')


    kaggle_set = "C:\\DeMarcus\\train"

    label_path="Z:\\projects\\idaho-bailiff\\C4\\Labeled_Malware_Family_Dataset\\trainLabels3.csv"
    #label_path="/Volumes/malware/samples/Kaggle/trainLabels.csv"

    labels,unique=read_csv(label_path)

    count=0
    found=0
    sample_list=[]
    for file in os.listdir(kaggle_set):
        if ".asm" in file:
            count+=1
            sample_list.append(os.path.join(kaggle_set,file))
            with open(os.path.join(kaggle_set,file)) as f:
                if ".text" in f.read():
                    found+=1

    print "Total samples", count
    print "Found .text", found

    opcode_list=[]
    label_listing=[]

    pool=Pool(maxtasksperchild=100)

    for results in pool.map(getOpcodes,zip(sample_list,repeat(labels))):
        if results:
            #print results[1]
            #print results[0]
            opcode_list.append(results[0])
            label_listing.append(results[1])

    print len(label_listing)
    #X=hash_vector_func_word(opcode_list)

    X=count_vector_func_word(opcode_list)
    print X.toarray()

    km = KMeans(n_clusters=len(unique), init='k-means++', max_iter=100, n_init=1,
                verbose=1)

    print("Clustering sparse data with %s" % km)
    start = time.time()
    km.fit(X)
    print("done in %0.3fs" % (time.time() - start))

    print("Homogeneity: %0.3f" % metrics.homogeneity_score(label_listing, km.labels_))
    print("Label listing",label_listing)
    print("Kmeans predictions",km.labels_)
