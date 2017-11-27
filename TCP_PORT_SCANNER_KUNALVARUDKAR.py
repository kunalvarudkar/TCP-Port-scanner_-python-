from scapy.all import *

class color:                                             # created class and defined colors 
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

#print color.CYAN + 'Hello World !' + color.END          # example for using the colors using the defined colors
print "\n"
print color.RED + 'GROUP 1 : ASSIGNMENT ON TCP PORT SCANNER ' + color.END
print "\n"
choice = input(color.CYAN + '1.TCP CONNECT SCAN\n2.SYN SCAN\n3.XMAS SCAN\n4.NULL SCAN\n5.ACK SCAN\n6.EXIT\n\nEnter your choice =' + color.END)

def output():
	print color.RED + 'Developed by => Kunal Varudkar => varudkar.kunal@gmail.com' + color.END 


if (choice==1):
   print "\n"
   print color.GREEN + '################### TCP CONNECT SCAN ###################' + color.END
   target = raw_input("Enter target IP address=")
   port = int(raw_input("Enter target Port address="))
   pack = sr1(IP(dst=target)/TCP(flags="S",dport=port),timeout=10)
   #pack.show()
   if pack is None:
   	print color.RED+ 'Port is Closed' + color.END
   elif(pack.haslayer(TCP)):
	if(pack.getlayer(TCP).flags==0x12):
		print color.RED + 'Port is Open' + color.END
	elif(pack.getlayer(TCP).flags==0x14):
		print color.RED + 'Port is Closed' + color.END
   else:
	print color.RED + 'Unknown state' + color.END
   output()

elif(choice==2):
   print "\n"
   print color.GREEN + '################### SYN SCAN ###################' + color.END
   target = raw_input("Enter target IP address=")
   port = int(raw_input("Enter target Port address="))
   pack = sr1(IP(dst=target)/TCP(flags="S",dport=port),timeout=10)
   #pack.show()
   if pack is None:
   	print color.RED + 'Port is Closed' + color.END
   elif(pack.haslayer(TCP)):
	if(pack.getlayer(TCP).flags==0x12):
                #sendpack=sr(IP(dst=target)/TCP(dport=port,flags="R"),timeout=10)
		print color.RED + 'Port is Open' + color.END
	elif(pack.getlayer(TCP).flags==0x14):
		print color.RED + 'Port is Closed' + color.END
   else:
       print color.RED + 'unknown state' + color.END

elif(choice==3):
	print "\n"
	print color.GREEN + '################### XMAS SCAN ###################' + color.END
	target = raw_input("Enter target IP address=")
	port = int(raw_input("Enter target Port address="))
	pack = sr1(IP(dst=target)/TCP(flags="FPU",dport=port),timeout=10)
	#pack.show()   removed bcoz pack dont hold any value
	if pack is None:
		print color.RED + 'Port is Open|Filtered'  + color.END
	elif(pack.haslayer(TCP)):
		if(pack.getlayer(TCP).flags==0x14):
			print color.RED + 'Port is Closed' + color.END
	elif(pack.haslayer(ICMP)):
		if(int(pack.getlayer(ICMP).type)==3 and int(pack.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			print color.RED + 'Filtered port' + color.END
        output()

elif(choice==4):
	print "\n"
	print color.GREEN + '################### NULL SCAN ###################' + color.END
	target = raw_input("Enter target IP address=")
	port = int(raw_input("Enter target Port address="))
	pack = sr1(IP(dst=target)/TCP(flags="",dport=port),timeout=10)
	#pack.show()   removed bcoz pack dont hold any value
	if pack is None:
		print color.RED + 'Port is Open|Filtered' + color.END
	elif(pack.haslayer(TCP)):
		if(pack.getlayer(TCP).flags==0x14):
			print color.RED + 'Port is Closed' + color.END
	elif(pack.haslayer(ICMP)):
		if(int(pack.getlayer(ICMP).type)==3 and int(pack.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			print color.RED + 'Filtered Port' + color.END
        output()

elif(choice==5):
	print "\n"
	print color.GREEN + '################### ACK SCAN ###################' + color.END
	target = raw_input("Enter target IP address=")
	port = int(raw_input("Enter target Port address="))
	pack = sr1(IP(dst=target)/TCP(flags="A",dport=port),timeout=10)
	#pack.show()   removed bcoz pack dont hold any value
	if pack is None:
		print color.RED + 'Stateful firewall presentn(Filtered)' + color.END
	elif(pack.haslayer(TCP)):
		if(pack.getlayer(TCP).flags==0x4):
			print color.RED + 'No firewalln(Unfiltered)' + color.END
	elif(pack.haslayer(ICMP)):
		if(int(pack.getlayer(ICMP).type)==3 and int(pack.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			print color.RED + 'Stateful firewall presentn(Filtered)' + color.END
        output()

elif(choice==6):
	exit()

else:
	exit()
