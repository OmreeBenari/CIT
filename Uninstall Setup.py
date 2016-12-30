import subprocess

'''
Will uninstall all nessesary modules to make CIT work.
'''

whl_list = ["setuptools-29.0.1-py2.py3-none-any.whl", "ipaddress-1.0.17-py2-none-any.whl", "enum34-1.1.6-py2-none-any.whl",
"idna-2.1-py2.py3-none-any.whl", "pyasn1-0.1.9-py2.py3-none-any.whl", "six-1.10.0-py2.py3-none-any.whl", "pycparser-2.17-py2.py3-none-any.whl",
"cffi-1.9.1-cp27-cp27m-win32.whl", "cryptography-1.6-cp27-cp27m-win32.whl", "paramiko-2.0.2-py2.py3-none-any.whl", "pyftpdlib-master.zip",
"pip-9.0.1-py2.py3-none-any.whl"]

for module in whl_list:
    subprocess.check_output("C:\\Python27\\python.exe -m pip uninstall -y {}".format(module), shell=False)
    print "[+] {} uninstalled successfully.".format(module)

print "\n[+] Done."
