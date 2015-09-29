import pe_class as p
import os
import sys
import time
from multiprocessing import Pool
import multiprocessing
from itertools import repeat
import re
from sklearn.feature_extraction.text import HashingVectorizer

try:
    import pefile
    import peutils
except ImportError:
    print 'pefile not installed, see http://code.google.com/p/pefile/'
    sys.exit()


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
    return p.fileName(path),p.getByteSets(path,pe,setSize),p.printable_strings(path),p.getOpcodes(pe,path)

#Function to extract strings of size 4 or longer
def tokenize(text):
    exp=re.compile('^(.{4,})$')
    return [tok.strip() for tok in exp.split(text)]


#Function that take a string of character input and creates a feature vector.  Appended is the name of the sample
def vector_func_char(l):
    vectorizer= HashingVectorizer(analyzer='char',input='content',decode_error='ignore',
                                 strip_accents='ascii',ngram_range=(1,1),n_features=262144)

    return str(l).split(" ")[0],vectorizer.fit_transform(str(l).replace(str(l).split(" ")[0],""))
    #return vectorizer.fit_transform(l)


#Function that take a string of words as input and creates a feature vector.  Appended is the name of the sample

def vector_func_word(l):
    vectorizer= HashingVectorizer(non_negative=True, stop_words='english' ,input='content',decode_error='ignore',
                                 strip_accents='ascii',n_features=262144,tokenizer=tokenize)

    return str(l).split(" ")[0],vectorizer.fit_transform(str(l).replace(str(l).split(" ")[0],""))
    #return vectorizer.fit_transform(l)



if __name__ == '__main__':


    then=time.time()

    #base_path="/Volumes/malware/samples/Evasive_Sample_Set/samples"
    base_path="Z:\\projects\\idaho-bailiff\\C4\\dataset_evasive_malware\\files\\samples"


    #sys.stdout = open('output_file2.txt', 'w')


    #Grab the path to all samples in directory
    l=[]
    for s in os.listdir(base_path):
        l.append(os.path.join(base_path,s))


    setSize=1
    sample_list1=[]
    sample_list2=[]

    #Collect features data from malware samples using multiprocessing
    pool=Pool(maxtasksperchild=25,processes=multiprocessing.cpu_count()-2)
    for results in pool.imap(printInfo,zip(l,repeat(setSize))):
            if results[1]:

                sample_list1.append(str(results[0])+" "+ str([" ".join(results[1])]))
                sample_list2.append((str(results[0])+" "+ str([" ".join(results[2])])))



    #for s in sample_list2:
    #    print tokenize(str(s).replace(str(s).split(" ")[0],""))


    processing_now=time.time()
    print "Processing Time:",processing_now-then
    print "Sample list 1 length",len(sample_list1)
    print "Sample list 2 length",len(sample_list2)


    #Create feature vector for character input
    split_list = lambda lst, sz: [lst[i:i+sz] for i in range(0, len(sample_list1), 250)]

    for s in split_list:
        for fv1 in pool.imap_unordered(vector_func_char,s):
            print fv1[1]
        pool.close()
        pool.join()
    print"*********************************"
    #Create feature vector for word input
    for fv2 in pool.imap_unordered(vector_func_word,sample_list2,chunksize=20):
        print fv2[1]

    #pool.close()
    #pool.join()

    total_now=time.time()
    print "Total Time", total_now-then




