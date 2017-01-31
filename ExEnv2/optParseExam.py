import sys
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-t", type="string", dest="target")
parser.add_option("-s", type="string", dest="source")
parser.add_option("-d", action="store_true", dest="d")
options, args = parser.parse_args()
print(options)
print(args)
