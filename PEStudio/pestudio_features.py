__author__ = 'temp'


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






