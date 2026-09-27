import sys

IAT_ADDRESS   = 0
MODULE_NAME   = 2
FUNCTION_NAME = 3

inputFile = sys.argv[1]
outputFile = sys.argv[2]

with open(outputFile, 'w') as idcFile:

    idcFile.write("#include <idc.idc>\n")
    idcFile.write("static main (void) {\n")

    with open(inputFile, 'r') as impscanFile:
        for line in impscanFile:
            impscanData = line.split()
            idcFile.write('\tMakeDword({0});\n'.format(impscanData[IAT_ADDRESS]))
            idcFile.write('\tMakeName({0}, "{1}");\n'.format(impscanData[IAT_ADDRESS],
                                                             impscanData[FUNCTION_NAME]))

    idcFile.write("}")    
