import pefile
import pe_class as p
import os
import sys
import time
import csv
from multiprocessing import Pool
from itertools import repeat
import chardet
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer,HashingVectorizer
import numpy as np




def printInfo((path,setSize)):


    pe=pefile.PE(path)
    """
    print p.fileName(path),"name"
    print p.fileSize(path), "bytes"
    print p.getMachineType(pe),"machine_type"
    print "packer/compiler:",p.compiler_or_packer_type(pe)
    print "resource",p.check_rsrc(pe)
    print p.getTimeInfo(pe), "compile_time"
    print p.getLinkerVersion(pe),"linker_version"
    print p.getSectionAlignment(pe), "section_alignment"
    print p.getNumSections(pe), "num_sections"
    print p.getEntryPointAddress(pe), "entry_point_address"
    print p.get_filetype_file(path), "file_type"

    print p.getSizeOfCode(pe), "code_size"

    print "i_dll:",p.getImportedDLLs(pe)
    print "i_functions:",   p.getImportedFunctions(pe)

    print "e_functions:",p.getExportedFunctions(pe)
    print "isPacked", p.checkIfPacked(pe)
    print "isPacked2",p.checkIfPacked2(pe)
    print "file_info:",p.getFileInfo(pe)
    sl = list(p.strings(path))
    print "strings",sl
    print "num_strange_sections",p.numStrangeSectionName(pe)
    print "sec_size_zero_virtual_not",p.checkSectionSizeZero(pe)
    print "raw_vs_virtual_larger_than_alignment",p.checkRawVsVirtualSection(pe)
    print "entropy_value_packed_or_encrypted?", p.checkEntropy(pe)

    #print "opcodes\n", p.getOpcodes(pe,path)
    #print p.fileName(path),"name"
    #for x in range(1,setSize+1):
    #    print "opcode_sets\n",p.getOpcodeSets(p.getOpcodes(pe,path),x)

    #for x in range(1,setSize+1):

    """
    return p.fileName(path),p.getByteSets(path,pe,setSize)



def vector_func(l):
    vectorizer= HashingVectorizer(analyzer='char',input='content',decode_error='ignore',
                                 strip_accents='ascii',ngram_range=(1,1),n_features=262144)
    #if l:
    #    l=l[2:-2]
    return str(l).split(" ")[0],vectorizer.fit_transform(str(l).replace(str(l).split(" ")[0],""))
    #return vectorizer.fit_transform(l)




if __name__ == '__main__':


    then=time.time()

    base_path="Z:\\projects\\idaho-bailiff\\C4\\dataset_evasive_malware\\files\\samples"


    c=1
    #sys.stdout = open('H:\\Desktop\\output_file.txt', 'w')

    l=[]
    for s in os.listdir(base_path):
        l.append(os.path.join(base_path,s))

    setSize=1
    sample_name=[]
    sample_list=[]
    import multiprocessing
    pool=Pool(maxtasksperchild=25,processes=multiprocessing.cpu_count()-2)

    for results in pool.imap(printInfo,zip(l,repeat(setSize))):
            if results[1]:
                #print str([" ".join(results[1])])
                #sample_list.append(results[1])
                sample_list.append(str(results[0])+" "+ str([" ".join(results[1])]))
                #sample_list.append(str(results[0])+" "+str([" ".join(results[1])]))


    #print len(sample_list)
    processing_now=time.time()
    print "Processing Time:",processing_now-then
    print "Sample list length",len(sample_list)


    #for s in sample_list:
    #    print str(s).replace(str(s).split(" ")[0],"")


    #data = pd.DataFrame()
    data=[]
    for fv in pool.imap_unordered(vector_func,sample_list,chunksize=20):
        #data.append(fv.toarray())
        print fv

    pool.close()
    pool.join()

    #for d in data:
    #    print d



    total_now=time.time()
    print "Total Time", total_now-then





