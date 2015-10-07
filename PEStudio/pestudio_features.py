__author__ = 'temp'

import re
import os
import sys
import pefile
from itertools import repeat
sys.path.append("C:\\DeMarcus\\cuckoo_parser\\Experimental")
import pe_class as p
import multiprocessing
from multiprocessing import Pool


"""
import xml.etree.ElementTree as ET


thresholds_tree = ET.parse('thresholds.xml')
thresholds_root = thresholds_tree.getroot()
strings_tree=ET.parse('strings.xml')
strings_root = strings_tree.getroot()



#for m in thresholds_root.iter('minimums'):
#    print m.tag,m.attrib

blist_strings=[]
for child in thresholds_root.iter('BlackListedStrings'):
    blist_strings.append(child.text)


print

for atype in strings_root.findall(strings_root.tag):
    print atype.text

"""

"""
#path = "H:\\Desktop\\strings_list.txt"
path ="functions.xml"

#pattern = r'"(.{4,})"'
pattern='"([^"]{5,})"'

with open(path,'r') as f:
    for line in f:
        if "lib" in line and "bl=\"1\"" in line and "name" in line:
            #print line.replace("\n","")
            print re.findall(pattern,line)
            #print re.sub(r'<.+?>','',line).replace("\n","").replace('\t','').replace("    \n","")
        #f.write(re.sub(r'<.+?>','',line).replace("\n","").replace('\t',''))
"""

def merge_dict(*dicts):
    result={}
    for dictionary in dicts:
        result.update(dictionary)
    return result

def process_sample((path,setSize,string_dict,import_dict,functions_dict,exts_dict)):
    if p.is_pe(path):

        pe=pefile.PE(path)

        strings=list(p.strings(path))

        if strings:
            for s in strings:
                for k in string_dict.keys():
                    if str(k).lower() == str(s).lower():
                        string_dict[k]=1
                        #print s,k,string_dict.get(k)
                for k in exts_dict.keys():
                    #This if statement makes sure that the file extension is the last part of the
                    #string being considered
                    if k in s and str(s).split(".")[1]==str(k).split(".")[1]:
                        #Checks to make sure a file name has no special characters besides slashes
                        if re.search("^[a-zA-Z0-9_/\\\]+$",str(s).split(".")[0]):
                            exts_dict[k]=1
                            #print s,k,exts_dict.get(k)

        imports = p.getImportedDLLs(pe)

        if imports:
            for i in imports:
                for k in import_dict.keys():
                    #if i == k:
                    if str(k) in str(i) and abs(len(k)-len(i))<2:
                        import_dict[k]=1
                        #print i,k,import_dict.get(k)

            for i in imports:
                for k in string_dict.keys():
                    if str(k) in str(i) and abs(len(k)-len(i))<2:
                        import_dict[k]=1
                        #print i,k,import_dict.get(k)


        functions = p.getImportedFunctions(pe)

        if functions:
            for f in functions:
                for k in functions_dict.keys():
                    if str(k) in str(f) and abs(len(k)-len(f))<2:
                        functions_dict[k]=1
                        #print f,k,functions_dict.get(k)


    return merge_dict(string_dict,import_dict,functions_dict,exts_dict)

"""
path = "H:\\Desktop\\strings2.txt"
    #path ="functions.xml"

    #pattern = r'"(.{4,})"'
    pattern='"([^"]{5,})"'

    with open(path,'r') as f:
        for line in f:
            #print line
            #if "lib" in line and "bl=\"1\"" in line and "name" in line:
                #print line.replace("\n","")
                #print re.findall(pattern,line)
            print re.sub(r'<.+?>','',line).replace("\n","").replace('\t','').replace("    \n","")
            #f.write(re.sub(r'<.+?>','',line).replace("\n","").replace('\t',''))


"""



if __name__ == '__main__':

    pool=Pool(maxtasksperchild=25,processes=multiprocessing.cpu_count())

    sys.stdout = open('dic_output.txt', 'w')
    bl_strings="H:\\Desktop\\blacklisted_strings.txt"
    bl_imports="H:\\Desktop\\blacklisted_imports.txt"
    bl_functions="H:\\Desktop\\blacklisted_functions.txt"
    exts="H:\\Desktop\\string_extensions.txt"

    base_path="Z:\\projects\\idaho-bailiff\\C4\\dataset_evasive_malware\\files\\samples"
    base_path="Z:\\users\\dmt101\\m_samples"

    functions_dict={}
    imports_dict={}
    strings_dict={}
    ext_dict={}
    with open(bl_functions,'r') as f:
        for line in f:
            functions_dict[line.replace("\n","")]=0
            #print line.replace("\n","")

    with open(bl_imports,'r') as f:
        for line in f:
            imports_dict[line.replace("\n","")]=0

    with open(bl_strings,'r') as f:
        for line in f:
            strings_dict[line.replace("\n","")]=0

    with open(exts,'r') as f:
        for line in f:
            ext_dict["."+line.replace("\n","")]=0


    l=[]
    for s in os.listdir(base_path):
        l.append(os.path.join(base_path,s))


    for results in pool.imap(process_sample,zip(l,repeat(1),repeat(strings_dict),repeat(imports_dict),repeat(functions_dict),repeat(ext_dict))):
        if results:
            print results

    #for sample in l:
    #    print process_sample((sample,1,strings_dict,imports_dict,functions_dict,ext_dict))
    #print functions_dict
    #print imports_dict
    #print strings_dict



