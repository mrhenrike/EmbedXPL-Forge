import re
import sys

OFFSET_FUNCTION_RE = r'(0x\w{8}) \((\w+)\)'
OFFSET             = 1
FUNC_NAME          = 2

funcInfo = {}

inputFile = sys.argv[1]
outputFile = sys.argv[2]

with open(inputFile, 'r') as ssdtFile:
    data = ssdtFile.readlines()
    for line in data:
        searchOutput = re.search(OFFSET_FUNCTION_RE, line)
        funcInfo.update({ searchOutput.group(OFFSET) : searchOutput.group(FUNC_NAME) })

with open(outputFile, 'w') as idcFile:
    
    idcFile.write("#include <idc.idc>\n")
    idcFile.write("static main (void) {\n")

    for offset in funcInfo.keys():
            idcFile.write('\tMakeDword({0});\n'.format(offset))
            idcFile.write('\tMakeName({0}, "Fake{1}");\n'.format(offset,
                                                             funcInfo[offset]))

    idcFile.write("}")    

    
