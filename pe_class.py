__author__ = 'dmt101'

import sys
import distorm3
import os
import string
import re
import magic
import numpy as np

try:
    import pefile
    import peutils
except ImportError:
    print 'pefile not installed, see http://code.google.com/p/pefile/'
    sys.exit()


def is_pe(filename):
	try:
		global pe
		pe = pefile.PE(filename)
		return True
	except:
		return False


#Obtain the time that the sample was compiled
def getTimeInfo(pe):

    if hasattr(pe,"FILE_HEADER"):
        return int(pe.FILE_HEADER.TimeDateStamp)
    else:
        return None


#Obtain number of sections with file header
def getNumSections(pe):
    if hasattr(pe,"FILE_HEADER"):
        return int(pe.FILE_HEADER.NumberOfSections)
    else:
        return None


#Determine the section that a given RVA is found within
def findSection(pe,address):
    sec=0

    for s in pe.sections:
        if hex(address) >= hex(s.VirtualAddress):
            if hex(address) <= hex(s.VirtualAddress+s.Misc):
                break
        sec+=1

    return sec



#Determine what type of system the sample can be run on
#or needs to be able to emulate
def getMachineType(pe):
    if hasattr(pe,'DOS_HEADER'):

        if pe.FILE_HEADER.Machine == 332:
            return "x86"

        elif pe.FILE_HEADER.Machine == 512:
            return "Intel Itanium"

        elif pe.FILE_HEADER.Machine == 34404:
            return "x64"
    else:
        return None

#Use peutil signature database to guess compiler/packer type
def compiler_or_packer_type(pe):
    if hasattr(pe,'DOS_HEADER'):
        signature= peutils.SignatureDatabase("C:\\bin\\UserDB.TXT")
        check=signature.match_all(pe,ep_only=True)
        #print "Compiler/Packer:",check

        return check
    else:
        return None

#Determine the file type of the given sample
#Figure out why python Magic does not work!!!!
def get_filetype_data(data):

    if sys.modules.has_key('magic'):
        try:
            return magic.from_buffer(data)
        except magic.MagicException:
            magic_custom = magic.Magic(magic_file='C:\\bin\\share\\misc\\magic')
            return magic_custom.from_buffer(data)
    return None

#Use magic module to determine the file type
def get_filetype_file(f):
    if sys.modules.has_key('magic'):
        try:
            return magic.from_file(file)
        except magic.MagicException:
            magic_custom = magic.Magic(magic_file='C:\\bin\\share\\misc\\magic')
            return magic_custom.from_file(f)
    return None

#Find resources found within file
def check_rsrc(pe):
    ret = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        i = 0
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = "%s" % resource_type.name
            else:
                name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if name == None:
                name = "%d" % resource_type.struct.Id
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            filetype = get_filetype_data(data)
                            lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                            sublang = pefile.get_sublang_name_for_lang( resource_lang.data.lang, resource_lang.data.sublang )
                            ret[i] = (name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, filetype, lang, sublang)
                            #ret[i] = (name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, lang, sublang)
                            i += 1
        if not ret:
            return None
        else:
            return ret
    else:
        return None


def get_num_rsrc(pe):
    if hasattr(pe,'DIRECTORY_ENTRY_RESOURCE'):
        return len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
    else:
        return None


#TODO: Find better measure of code complexity to identify programmer traits
"""
def getCodeComplexity(pe,path):
    if len(getImportedFunctions(pe))>0:
        print int(getSizeOfCode(pe)),len(getImportedFunctions(pe))
        return int(getSizeOfCode(pe))/len(getImportedFunctions(pe))
    else:
        return 0
"""


#TODO: Develop way of determining the average function size with a sample
#def avgFuncSize()



#TODO: Find metric for Graph Complexity
#def graphComplexity()

#Get size of Sample
def fileSize(path):
    return os.stat(path).st_size

#Get name of sample
def fileName(path):
    return os.path.basename(path)

#Find all imported Dlls for sample
def getImportedDLLs(pe):
    if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
        dict=[]
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            #print entry.dll
            dict.append(entry.dll)

        return dict
    else:
        return None

#Find all imported functions for sample
def getImportedFunctions(pe):
    if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
        list=[]

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    list.append(imp.name)
                else:
                    list.append(imp.ordinal)

        return list
    else:
        return None

#Check to see if the sample has a low number of imports
#as well as if the sample has LoadLibrary & GetProcAddress
def checkIfPacked(pe):
    if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
        list={}

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                list.setdefault(imp.name)

        try:
            if len(list) <= 10:
                if list.keys().index('GetProcAddress'):
                    if list.keys().index('LoadLibraryA') or list.keys().index('LoadLibrary'):
                        return True
        except:
            return False
    return None

def checkIfPacked2(pe):
    return peutils.is_probably_packed(pe)


#Find all exported functions in sample
def getExportedFunctions(pe):
    if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
        list=[]
        for exports in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            list.append(exports.name)
        if not list:
            return None
        else:
            return list
    else:
        return None

#Produces all FileVersion information associated with the file
def getFileInfo(pe):
    list=[]
    if hasattr(pe,'FileInfo'):
        for entry in pe.FileInfo:
            if hasattr(entry, 'StringTable'):
                for st_entry in entry.StringTable:
                    for str_entry in st_entry.entries.items():
                        list.append(str_entry)

                    return list
    if not list:
        return None


#Displays all strings from a file
def strings(filename, min=4):
    with open(filename, "rb") as f:
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""

#All section under PE Optional Header
#? What happens to linker if size of optional header is zero?
def getLinkerVersion(pe):
    if hasattr(pe,'OPTIONAL_HEADER'):
        return str(pe.OPTIONAL_HEADER.MajorLinkerVersion)+"."+str(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    else:
        return None


def getSectionAlignment(pe):
    if hasattr(pe,'OPTIONAL_HEADER'):
        return pe.OPTIONAL_HEADER.SectionAlignment
    else:
        return None

def getSizeOfCode(pe):
    if hasattr(pe,'OPTIONAL_HEADER'):
        return pe.OPTIONAL_HEADER.SizeOfCode
    else:
        return None


def checkSectionSizeZero(pe):
    if hasattr(pe,'DOS_HEADER'):
        list=[]
        for section in pe.sections:
            #print section.Name,section.SizeOfRawData
            if section.SizeOfRawData == 0 and section.Misc != 0:
                list.append(re.sub('\W', '',str(section.Name)))

        if list:
            return True,list
        else:
            return False
    else:
        None

def checkRawVsVirtualSection(pe):
    if hasattr(pe,'DOS_HEADER'):
        list=[]
        for section in pe.sections:
            #print section.Name
            #print "Virt",section.Misc,"Raw",section.SizeOfRawData,"align",getSectionAlignment(pe)
            if section.Misc-section.SizeOfRawData > getSectionAlignment(pe):
                list.append(re.sub('\W', '',str(section.Name)))
        if list:
            return True,list
        else:
            return False
    else:
        None


def checkEntropy(pe):
    if hasattr(pe,'DOS_HEADER'):
        list=[]
        for section in pe.sections:
            #print section.Name,section.get_entropy()
            #print section
            if (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
                #print section.Name
                list.append(re.sub('\W', '',str(section.Name)))

        if list:
            return True,list
        else:
            return False
    else:
        None



#Get Entry Point Address
def getEntryPointAddress(pe):
    if hasattr(pe,'OPTIONAL_HEADER'):
        return pe.OPTIONAL_HEADER.AddressOfEntryPoint
    else:
        return None


def getMagicNumber(pe):
    if hasattr(pe,'OPTIONAL_HEADER'):
        return hex(pe.OPTIONAL_HEADER.Magic)
    else:
        return None

def numStrangeSectionName(pe):
    if hasattr(pe,'DOS_HEADER'):
        list=[]
        section_list=["arch","bss","data","debug","debug$S","debug$T","edata","idata",
                      "pdata","rdata","reloc","rsrc",'text',"tls",".xdata","drectve","code"]
        c=0
        for section in pe.sections:
            string=re.sub('\W', '',str(section.Name))
            if string.lower() not in section_list:
                #print section.Name
                list.append(re.sub('\W', '',str(section.Name)))
                c+=1
        if list:
            return c,list
        else:
            return c
    else:
        return None

#Get opcode for the given malware sample
def getOpcodes(pe,file_path):
    if hasattr(pe,'DOS_HEADER'):
        l=[]

        sec=findSection(pe,getEntryPointAddress(pe))

        #print len(pe.sections)
        if sec < len(pe.sections):
            #print sec
            #print "Inside",pe.sections[sec].Name

            #Grab instructions within section that contains the entry point
            instructions=distorm3.Decode(pe.OPTIONAL_HEADER.ImageBase, open(file_path,'rb').read(),distorm3.Decode32Bits)

            for i in instructions:
                #print i[0],i[1],i[2],i[3]
                #print "0x%08x (%02x) %-20s %s" % (i[0],  i[1],  i[3],  i[2])

                #Make sure instruction is within after entry point but before the end of the section
                if i[0] >= (getEntryPointAddress(pe)+pe.OPTIONAL_HEADER.ImageBase):
                    if i[0] < (getEntryPointAddress(pe)+pe.sections[sec].SizeOfRawData+pe.OPTIONAL_HEADER.ImageBase):
                        #Grab opcode for the instruction being used
                        l.append("".join(list(i[3])[:2]))
            return l
        else:
            return None
    else:
        return None

#Get the list of the opcode sets for a given malware sample
def getOpcodeSets(opCodeList,setSize):
    s1=0
    s2=setSize
    opcodeSet=[]
    #l= getOpcodes(pe,file_path)
    if opCodeList:
        while s2 <= len(opCodeList):
            opcodeSet.append(opCodeList[s1:s2])
            s1 +=1
            s2 +=1

        return opcodeSet
    else:
        return None




def getByteSets(path,pe,setSize):

    #Determine the section the RVA is found in
    sec=findSection(pe,pe.OPTIONAL_HEADER.BaseOfCode)

    #Check if valid section is found
    if sec < len(pe.sections):

        #Formula for file_offset = RVA - VirtualAddress +RawDataPointer
        file_offset = pe.OPTIONAL_HEADER.BaseOfCode-pe.sections[sec].VirtualAddress+pe.sections[sec].PointerToRawData

        s1=file_offset
        s2=file_offset+setSize

        byte_ngram=[]
        with open (path,'rb') as f:
            file = f.read()
            #Find byte n-grams until the end of the section is reached
            while s2 <= int(file_offset+pe.sections[sec].SizeOfRawData):
                byte_ngram.append(file[s1:s2])
                s1+=1
                s2+=1

        return byte_ngram
    else:
        return None