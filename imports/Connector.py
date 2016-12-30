import paramiko
import telnetlib
import re
import getpass
import socket
import subprocess
import os
import platform
import sys
import threading
import logging
from pyftpdlib.log import config_logging
from time import sleep
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

global username
global password
global server_ip

class Connector:
	def __init__(self, path, ip):
		self._path = path
		self._ip = ip

	def connect(self):
		'''
		this function checks if the telnet or the ssh port is open and calls the suitable func.

		'''
                global username
                global password
                global server_ip 
		username = raw_input("Enter username to device: ")
		password = getpass.getpass("Enter password to device: ")

		try:
			port = 22
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			network_est = sock.connect_ex((self._ip, port))
			if (network_est!=0):
				port = 23
				print "[-] Connection via ssh can't be established, trying to connect via telnet"
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				network_est = sock.connect_ex((self._ip, port))
				if (network_est!=0):
					print "[-] Connection via telnet can't be established. Exiting tool."
					sys.exit(0)
				else:
					print "[+] Connection via telnet is avialble."
					server_ip = sock.getsockname()[0]
					sock.close()
			else:
				print "[+] Connection via ssh is avialble."
				server_ip = sock.getsockname()[0]
				sock.close()
		except:
			print "[-] Error while connecting to the device. Exiting tool."
			sys.exit(0)

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		network_est = sock.connect_ex((server_ip, 21))
		if (network_est!=0):
			print "[+] No running FTP server found on computer. Starting FTP server on local computer.."
                        t = threading.Thread(target=self.startftp,args=(server_ip,))
			t.start()

		if (port==22):
			self.ssh_conn()
		else:
			self.telnet_conn()

	def ssh_conn(self):
		'''	
		This function manages the connection via ssh to the Device 
		and throws the IOS image, and the CoreDump
		'''
		try:
			ssh=paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect(self._ip, port=22, username=username, password=password)
			chan = ssh.invoke_shell()
		except ValueError:
			print "[+] There was and error trying to make a connection with the device."
			sys.exit(0)

		sleep(2)
                chan.send("terminal length 0\n")
                sleep(2)
                chan.send("show version \n")
                sleep(2)
		sh_ver = chan.recv(50000)

		version = re.search(r"Version (\d+\.\d+)\(.+\).+RELEASE", sh_ver).group(1)

		print "[+] Version of device is: {}".format(version)

		print "[+] Getting ready to copy IOS image..."
		try:
			chan.send("en\n")
			sleep(2)
			if re.match(r"%nter", chan.recv(50000))!= None:
                                chan.send(password + "\n")
                                sleep(2)
			chan.send("conf t\n")
			sleep(2)
			chan.send("ip ftp username user\n")
			sleep(2)
			chan.send("ip ftp password 12345\n")
			sleep(2)
			chan.send("exit\n")
			sleep(2)
			chan.send("show flash:\n")
			sleep(2)
			bin_file = re.search(r"[a-zA-Z.0-9-]+bin", chan.recv(50000)).group(0)
			chan.send("copy ftp flash\n")
			sleep(2)
			chan.send(server_ip + "\n")
			sleep(2)
			chan.send(bin_file + "\n")
			sleep(2)
			chan.send("{}\\OSimage.bin \n".format(self._path))

			
			if re.match(r"%Warning:There is a file already existing", chan.recv(50000))!= None:
				chan.send("\n")
				
                        print "[+] Copying IOS image..."
                        
			check = chan.recv(50000)
			flag = 1
			while flag == 1:
                                check = chan.recv(50000)
                                if re.search(r"#$", check)!=None:
                                        flag = 2
                                sleep(5)
					
			if re.search(r"bytes copied", check)!=None:
			   	print "[+] Core was successfully dumped to server"
			elif re.search(r"(%[A-Za-z :/0-9.()]+)", check)!=None:
				print "[+] Exiting tool with error: {}".format(re.search(r"(%[A-Za-z :/0-9.()]+)", check).group(1))
				sys.exit(0)
			else:
				print "[+] Unknown error. Exiting tool."
				sys.exit(0)

		except Exception as e:
                        print str(e)
			print "[+] There was an error while copying IOS image"
			sys.exit(0)

		if (float(version)==12.4 or float(version)==15.0):

			print "[+] Creating core dump"
			try:
				chan.send('conf t\n')
				sleep(2)
				chan.send('exception protocol ftp\n')
				sleep(2)
				chan.send('exception dump {}\n'.format(server_ip))
				sleep(2)
				chan.send('exception core-file {}\n'.format(path))
				sleep(2)
				chan.send('exit\n')
				sleep(2)
				chan.send('write core\n')
				sleep(2)
				chan.send("\n")
				sleep(2)
				chan.send('{}\\Core_Dump\n'.format(self._path))

				print "[+] Copying core dump..."
				if re.match(r"%Warning:There is a file already existing", stdout)!=None:
					chan.send("\n")

				check = chan.recv(50000)
                                flag = 1
                                while flag == 1:
                                        check = chan.recv(50000)
                                        if re.search(r"#$", check)!=None:
                                                flag = 2
                                        sleep(10)

				if re.search(r"bytes copied", check)!=None:
					print "[+] Core was successfully dumped to server"
				elif re.search(r"(%[A-Za-z :/0-9.()]+)", check)!=None:
					print "[+] Exiting tool with error: {}".format(re.search(r"(%[A-Za-z :/0-9.()]+)", check).group(1))
					sys.exit(0)
				else:
					print "[+] Unknown error. Exiting tool."
					sys.exit(0)
			except:
				print "[+] There was an error creating core dump"
				sys.exit(0)

		else:
			print "[+] Version of the device is older than 12.4 so it is impossible to create core-dump"
			sys.exit(0)


	def telnet_conn(self):
		'''	
		This function manages the connection via telnet to the Device 
		and throws the IOSImage, and the CoreDump
		'''
		try:
			tn = telnetlib.Telnet(self._ip)
			sleep(2)
			tn.write(username + "\n")
			sleep(2)
			tn.write(password + "\n")

		except:
			print "[+] There was and error trying to make a connection with the device."
			sys.exit(0)

		tn.write("terminal length 0 \n")
		sleep(2)
		tn.write("show version \n")
		sleep(2)
		sh_ver = tn.read_until("RELEASE", 5)
		version = re.search(r"Version (\d+\.\d+)\(.+\).+RELEASE", sh_ver).group(1)
		tn.read_until("^&%&^%$#", 5)

		print "[+] Getting ready to copy IOS image..."
		try:
			tn.write("en\n")
			sleep(2)
			if re.match(r"%nter", chan.recv(50000))!= None:
                                chan.send(password + "\n")
                                sleep(2)
			tn.write(password + "\n")
			sleep(2)
			tn.write("conf t\n")
			sleep(2)
			tn.write("ip ftp username user\n")
			sleep(2)
			tn.write("ip ftp password 12345\n")
			sleep(2)
			tn.write("exit\n")
			sleep(2)
			tn.write("show flash:\n")
			sh_flash = tn.read_until(".bin", 5)
			bin_file = re.search(r"[a-zA-Z.0-9-]+bin", sh_flash).group(0)
			tn.read_until("^&%&^%$#", 5)
			tn.write("copy ftp flash\n")
			sleep(2)
			tn.write(server_ip + "\n")
			sleep(2)
			tn.write(bin_file + "\n")
			sleep(2)
			tn.write("{}\\OSimage.bin\n".format(self._path))
			check = tn.read_until("^&%&^%$#", 5)

			if re.search(r"%Warning:There is a file already existing", check)!=None:
			   	print "[+] File with same name exists, it'll be overwritten"
				sleep(2)
				tn.write("\n")

			print "[+] Starting to copy IOS image..."

			check = tn.read_until("^&%&^%$#", 5)
			flag = 1
                        while flag == 1:
                                check = tn.read_until("^&%&^%$#", 5)
                                if re.search(r"#$", check)!=None:
                                        flag = 2
                                sleep(5)

                        print "5"
			if re.search(r"bytes copied", check)!=None:
				print "[+] Successfully copied IOS image"
			elif re.search(r"(%[A-Za-z :/0-9.()]+)", check)!=None:
				print "[+] Exiting tool with error: {}".format(re.search(r"(%[A-Za-z :/0-9.()]+)", check).group(1))
				sys.exit(0)
			else:
				print "[+] Unknown error. Exiting tool."
				sys.exit(0)
		except:
			print "[+] There was an error while copying IOS image."
			sys.exit(0)


		if (float(version)==12.4 or float(version)==15.0):

			ftp_server()
			print "[+] Creating core dump. This operation might take a while.."
			try:
				tn.write("conf t\n")
				sleep(2)
				tn.write("exception protocol ftp\n")
				sleep(2)
				tn.write("exception dump {}\n".format(server_ip))
				sleep(2)
				tn.write("exception core-file {}\n".format(path))
				sleep(2)
				tn.write("exit\n")
				sleep(2)
				tn.write("write core\n")
				sleep(2)
				tn.write("\n")
				sleep(2)
				tn.write("{}\\Core_Dump\n".format(self._path))
				
				print "[+] Starting to copy core..."
				flag = 1
				while flag == 1:
					check = tn.read_until("^&%&^%$#", 5)
					if re.search(r"#$", check)!=None:
						flag = 2
					sleep(5)
					
				if re.search(r"bytes copied", check)!=None:
					print "[+] Core was successfully dumped to server"
				elif re.search(r"(%[A-Za-z :/0-9.()]+)", check)!=None:
					print "[+] Exiting tool with error: {}".format(re.search(r"(%[A-Za-z :/0-9.()]+)", check).group(1))
					sys.exit(0)
				else:
					print "[+] Unknown error. Exiting tool."
					sys.exit(0)
			except:
				print "[+] There was an error creating core dump"
				sys.exit(0)

		else:
			print "[+] Version of the device is older than 12.4 so it is impossible to create core-dump"
			sys.exit(0)

	def startftp(self,server_ip):
                '''
                this function is a tiny ftp server, that will start if local machine has no ftp client running.
                '''
		try:
			authorizer = DummyAuthorizer()

   			authorizer.add_user('user', '12345', self._path, perm='elradfmwM')

  			handler = FTPHandler
  			handler.authorizer = authorizer

 			handler.banner = "pyftpdlib based ftpd ready."

  			address = (server_ip, 21)
  			server = FTPServer(address, handler)

  			server.max_cons = 256
 			server.max_cons_per_ip = 5

 			config_logging(level=logging.ERROR)
 			server.serve_forever()
 			print "[+] ftp Server Started Succesfully."
 		
 		except ValueError:
 			print "[-] Unable to start the ftp server. \n exiting."
		
