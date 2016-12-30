import subprocess
import re
import Naft.naftICD as ICD
import Naft.naftGFE as GFE
from ReportHandler import * 
import optparse
import glob
import time


class InvestigationHandler:
	'''
	this class will manage the entire Investigation.
	'''

	def __init__(self,DumpFile,path):
		self._path = path
		self._DumpFile = DumpFile
		self._regions = ""
		self._cwstrings = ""
		self._heap = ""
		self._processes = ""
		self._integritycheck = ""
		self._events = ""
		self._checktext= ""
		self._history = ""
		self._frames = ""
		self.oParser = optparse.OptionParser()
		self.oParser.add_option('-d', '--dump', default=False, help='dump data')
		self.oParser.add_option('-D', '--dumpraw', default=False, help='dump raw data')
		self.oParser.add_option('-s', '--strings', default=False, help='dump strings in data')
		self.oParser.add_option('-m', '--minimum', type=int, default=0, help='minimum count number of strings')
		self.oParser.add_option('-g', '--grep', default='', help='grep strings')
		self.oParser.add_option('-r', '--resolve', default=True, help='resolve names')
		self.oParser.add_option('-f', '--filter', default='' ,help='filter for given name')
		self.oParser.add_option('-a', '--raw', default=False, help='search in the whole file for CW_ strings')
		self.oParser.add_option('-w', '--write', default=False, help='write the regions or heap blocks to disk')
		self.oParser.add_option('-t', '--statistics', default=False, help='Print process structure statistics')
		self.oParser.add_option('-y', '--yara', help='YARA rule (or directory or @file) to check heaps')
		self.oParser.add_option('--yarastrings', default=False, help='Print YARA strings')
		self.oParser.add_option('--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
		self.oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
		self.oParser.add_option('-x', '--duplicates', action='store_true', default=True, help='include duplicates in Frames')
		self.oParser.add_option('-T', '--template', help='filename for the 010 Editor template to generate')
		self.oParser.add_option('-b', '--buffer', default=False, help='Buffer file in 100MB blocks with 1MB overlap')
		self.oParser.add_option('-p', '--options', default=False, help='Search for IPv4 headers with options')
   		self.oParser.add_option('-o', '--ouitxt', help='ouitxt filename to filter MAC addresses with unknown ID')
   		self.oParser.add_option('-S', '--buffersize', type='int', default=100, help='Size of buffer in MB (default 100MB)')
   		self.oParser.add_option('-O', '--bufferoverlapsize', default=1, help='Size of buffer overlap in MB (default 1MB)')
   		self.oParser.add_option('-i', '--ip', help='Debug')
   		self.options, self.args = self.oParser.parse_args()
   		


	def get_regions(self,report):
		'''
		this function will try to get the regions out of the memory 
		coredump file
		'''
		try:
			print "[+] Startnig to analyze Regions"
			self._regions= ICD.IOSRegions(self._DumpFile)
			
			report.printdata("Regions",self._regions)
			print "Done."
			#print self._regions
		except:
			report.printdata("Regions","[-] Could not get regions.")
			print "[-] Could not get regions. \n"

	def get_CWStrings(self,report):
		'''
		this function will try to get the CW Strings out of 
		the memory coredump file
		'''
		try:
			print "[+] Startnig to analyze CWStings"
			self._cwstrings= ICD.IOSCWStrings(self._DumpFile)
			report.printdata("CW Strings",self._cwstrings)
			print "Done."
			#print self._cwstrings
		except:
			report.printdata("CW Strings","[-] Could not get CWStrings.")
			print "[-] Could not get CWStrings. \n"
			
	def get_Heap(self,report):
		'''
		this function will try to get the Heap out of the memory coredump file.
		it can filter specified blocks of it by filtering
		its name, and also can dump the strings of those blocks.
		filter is configured by the -f option on the oParser.
		strings is configured by the -s option on the oParser.
		''' 
		try:
			print "[+] Startnig to analyze heap"
			self._heap = ICD.IOSHeap(self._DumpFile,self.options)
			report.printdata("Heap",self._heap)
			print "Done."

		except:
			report.printdata("Heap","[-] Could not get Heap stacture.")
			print "[-] Could not get Heap stacture. \n"


	def get_frames(self,report):
		'''
		this function will try to get Packet frames out of the memory image, and from the heap
		to Pcap files from the coredump file
		'''
		try:
		
			print "[+] Startnig to analyze heap for frames."
			iomemFileName = [self._path+ "coreiomem"]
			iomemFileName = sum(map(glob.glob, iomemFileName), [])
			GFE.ExtractIPPacketsFromFile(self._path + "Evidence.pcap",iomemFileName,self.options)
			report.printdata("Frames","Created the Pcap file in the investigation path.")
			print "Done."



		except:
			report.printdata("Frames","[-] Could not create a Pcap file.")
			print "[-] Could not create a Pcap file."
	

	def get_Processes(self, report):
		'''
		this function will try to get the processes running on the Device
		out of the memory image	from the coredump file
		'''
		try:
			print "[+] Startnig to analyze Processes"
			self._processes = ICD.IOSProcesses(self._DumpFile,self.options)
			report.printdata("Processes",self._processes)
			print "Done."
			
		except:
			report.printdata("Processes","[-] Could not get Processes.")
			print "[-] Could not get Processes."

	def get_integritycheck(self,report):
		'''
		this function will try to perform an integrity check of the heap
		out of the memory coredump file
		'''
		try:
			print "[+] Startnig to Perform Integrity Check on the heap"
			self._integritycheck = ICD.IOSIntegrityText(self._DumpFile,self.options)
			report.printdata("Integrity Check",self._integritycheck)
			print "Done."
			

		except:
			report.printdata("Integrity Check","[-] Could not perform Integrity Check on the Heap.")
			
			print "[-] Could not perform Integrity Check on the Heap.\n"



	def get_history(self,report):
		'''
		this function will try to get the 
		command history out of the memory coredump file

		'''
		try:

			print "[+] Startnig to analyze history"
			self._history= ICD.IOSHistory(self._DumpFile,self.options)
			
			if len(self._history) > 5 :
				report.printdata("History",self._history)
			else:
				report.printdata("History","No History Found")
				#print "[+] No History Found"
			print "Done."
		except:
			report.printdata("History","[-] Could not get the command history.")
			print "[-] Could not get the command history."	

	def checktext(self,report):
		'''
		this function will try to compare the instructions in the code region of 
		the core dump, with the instructions in the code section of the image.
		These should be identical. Differences indicate changes in memory.
		'''
		try:
			print "[+] Startnig to perform the check text examination"
			OSimageFilename=self._path+'\\OSimage.bin'
			self._checktext= ICD.IOSCheckText(self._DumpFile,OSimageFilename,self.options)
			report.printdata("Check Text Examination",self._checktext)
			print "Done."
		except:
			report.printdata("Check Text Examination","[-] Could not preform the check.")
			print "[-] Could not preform the check.\n"

	def get_events(self, report):
		'''
		this function will try to get the 
		event found in the memory coredump file
		'''

		try:
			print "[+] Startnig to analyze Events"
			self._events = ICD.IOSEvents(self._DumpFile,self.options)
			if len(self._events) > 5:
				report.printdata("Events",self._events)
				print "Done"
			else: 
				report.printdata("Events","[-] Could not find events.")
				print "[-] Could not find events.\n"

		except:
			report.printdata("Events","[-] Could not preform the check.")
				
			print "[-] Could not preform the check.\n"



