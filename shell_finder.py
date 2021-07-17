import os
import sys
from time import time
import requests
from datetime import datetime
from requests.packages import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#for personal use only
#don't forget to give credit, if copilot try to steal XD or if you copy paste.
endpoints = ['/aspnet_client/', '/owa/auth/','/OAB/', '/owa/auth/15.1.2044/scripts/premium/', '/owa/auth/Current/themes/resources/',  '/ecp/auth/', '/ews/']
vulnerableText = 'OAB (Default Web Site)'
foundShell = open(datetime.now().strftime("%d-%m-%Y")+'-shellFound.txt', 'w')

class colors:
        def __init__(self):
                self.green = "\033[92m"
                self.blue = "\033[94m"
                self.bold = "\033[1m"
                self.yellow = "\033[93m"
                self.red = "\033[91m"
                self.end = "\033[0m"
addColor = colors()

def checkArg():
   if len(sys.argv) <= 2:
      usage()
      sys.exit(0)

def banner():
   print("""%s
   /$$$$$$$$  /$$$$$$  /$$$$$$$$
   | $$_____/ /$$__  $$| $$_____/
   | $$      | $$  \__/| $$      
   | $$$$$   |  $$$$$$ | $$$$$   
   | $$__/    \____  $$| $$__/   
   | $$       /$$  \ $$| $$      
   | $$$$$$$$|  $$$$$$/| $$      
   |________/ \______/ |__/ 

   CVE-2021-26855
   Tool Author: D0rkerDevil, Rudra0x01     
                        %s""" %(addColor.yellow, addColor.end))

def usage():
   banner()
   print ('Usage:\n')
   print ('$ python %s domain_list.txt shellname.txt' %(sys.argv[0]))

def checkShell(stripDomainArg, stripEndpointArg, stripShellArg):
   isShell = requests.get('https://%s%s%s' %(stripDomainArg, stripEndpointArg, stripShellArg), timeout=None, verify=False)
   if vulnerableText in isShell.text:
      foundShell.write('https://%s%s%s\n' %(stripDomainArg, stripEndpointArg, stripShellArg))
      return '%s | Status: %sShell Found!%s' %(isShell.url, addColor.red, addColor.end)
   else:
      return '%s | Status: %sShell Not Found!%s' %(isShell.url, addColor.green, addColor.end)

start = time()
checkArg()
banner()

processes = []
with ThreadPoolExecutor(max_workers=50) as executor:
   domain = sys.argv[1]
   shell = sys.argv[2]
   try:
      with open(domain) as domainList:
         for lineDomain in domainList.read().splitlines():
            with open(shell) as shellName:
               for lineShell in shellName.read().splitlines():
                  for endpoint in endpoints:
                     processes.append(executor.submit(checkShell, lineDomain, endpoint, lineShell))
   except Exception as e:
      print(e)

for task in as_completed(processes):
    print(task.result())

print(f'\nTime taken: {time() - start}')
