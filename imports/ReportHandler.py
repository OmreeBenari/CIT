
class ReportHandler: 
	'''
	this class will manage the entire Investigation Report.
	'''

	def __init__(self, path):
		self._path = path
		self._filename = ""
		self._filehandler = ""
		self._br = '\n==============================================================\n\n'


	def InitiateDocument(self, date, ip):
		'''
		this function will create a file and a template of the report.
		including a little background about the investigation.
		'''
		self._filename = self._path + "Investogation_Report"

		self._filehandler = open(self._filename+".html",'wb')
		self._filehandler.write("<title> Investigation Report </title> <hr><br>\n")
		self._filehandler.write("<center><head> <h1>Investigation Report</h1></head></center><br>\n")
		self._filehandler.write("<hr><br><br>\n")
		self._filehandler.write("<h3><u>	Background:</u></h3><br>\n")
		self._filehandler.write("<br><br>\n\n")
		self._filehandler.write("<b>	Date of investigation:</b> {}<br><br>\n\n".format(date))
		self._filehandler.write("<b>	Device IP:</b> {}<br><br><br><br><br>\n".format(ip))
		self._filehandler.write('<p style="color:blue;"><center>Generated by CIT- Cisco Invastigation Toolkit<br> By Omree Benari & Miryam Adjiashvili (c) </center></p>\n')
		self._filehandler.write("<hr><br><br><br><br><br>")
		
		
	def printdata(self, header, body):
		'''
		this function will get the Data and the title to print,
		and will print that in the Investigation file.
		'''

		self._filehandler.write("<body><u>{}:</u><br>\n".format(header))
		
		self._filehandler.write('<div style:="color:#D3D3D3">\n<table>{}\n</table><br><br><div>\n</body>\n'.format(body))
		
