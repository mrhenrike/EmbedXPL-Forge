import sys
import pefile

inputFile = sys.argv[1]
output = sys.argv[2]

pe = pefile.PE(inputFile)
pe.parse_data_directories()

outputFile = open(output, 'w')

for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	functionRVA = exp.address
	functionName = exp.name.decode('utf-8')
	toWrite = '{0}\n'.format(functionName)
	outputFile.write(toWrite)

outputFile.close()
