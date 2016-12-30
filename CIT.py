

# an automatic tool for invastigation of a Cisco Device.
# versions 12.4 and 15.0
#Copyright (c) 2016 Omree Benari & Miryam Adjiashvili
#

__name__ = "CIT- Cisco invastigation Toolkit"
__authors__ = ["Omree Benari", "Miryam Adjiashvili"]
__version__ = "0.1"
__version_name__ = "CIT"
__license__ = "GPLv3"

import sys
import time
import string
import optparse
import re
import subprocess
import optparse
import imports.Invetigator as INV
import imports.Connector as CON
import imports.ReportHandler as REP



class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'

def banner():
	a  = "     ____ ___ _____ \n"
 	a += "    / ___|_ _|_   _|\n"
 	a += "   | |    | |  | |   \n"
 	a += "   | |___ | |  | |  \n"
	a += "    \____|___| |_|  \n"
	a+= " ========================\n"
	a+= "The Live Cisco Invastigation Toolkit \n" 
	a+= "the lazy way to invetigate a live suspicious Network Device,\n"
	#a+= "it is excecuted on the suspicious machine and checks its Registry,\n"
	#a+= "Installed apps, Services, Prefetches, and memory image (via volatility.)\n"
	a+= "Type " + sys.argv[0] + " -h to get help.\n"
	print a



#''' Argu ment Parsing is done here '''
parser = optparse.OptionParser(usage='usage:' + sys.argv[0]+' [options] -i ip -p path')
parser.add_option('-p', '--Path',type=str, dest='path', default="", help="Path to the investigation directory.")
parser.add_option('-i', '--IP',type=str, dest='ip',default="", help="IP of the device to invetigate")
parser.add_option('-v', '--version', action="store_true", dest="ver_flag", default=False, help="Print version information.")
(options, args) = parser.parse_args()



#''' Test for -v flag '''
ver_flag = options.ver_flag
if ver_flag:
	banner()
	print "Version: " + __version__
	sys.exit(0)

if options.path == '':
	banner()
	sys.exit(0)

if options.ip == '':
	banner()
	sys.exit(0)


''' Get basic handlers '''


inv = INV.InvestigationHandler(options.path + "12.4", options.path)
conn = CON.Connector(options.path,options.ip)
rep = REP.ReportHandler(options.path)


'''
#######################################
     Real program starts here
#######################################
'''
date = time.ctime(time.time())

banner()

print "\n\nstarted investigation in {}\n".format(date)

# Create the report Document
rep.InitiateDocument(date, options.ip)

# connect to the Device and perform IOS.bin copy and CoreDump
conn.connect()

inv.get_regions(rep)
inv.get_CWStrings(rep)
inv.get_integritycheck(rep)
inv.get_frames(rep)
inv.get_Processes(rep)
inv.checktext(rep)
inv.get_history(rep)
inv.get_events(rep)
inv.get_Heap(rep)


