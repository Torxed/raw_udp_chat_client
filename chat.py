#!/usr/bin/python3

import curses, shutil
import socket, signal
import fcntl, ctypes
import struct
import binascii
from collections import OrderedDict as odict
from time import sleep
from threading import Thread
from threading import enumerate as t_enum
from random import randint #REMOVE

def sig_handler(signal, frame):
	global core
	global promisciousMode

	promisciousMode.off()
	core['data'].close()

	terminate(core['main_screen'])
	exit(0)

def bin_int(num):
	return struct.pack('!h', num)

def checksum(data):
	c = 0
	for index, c_int in enumerate(data):
		if index & 1:
			c += int(c_int)
		else:
			c += int(c_int) << 8
	return c

def struct_frame(message, addr='127.0.0.1', port=5554):
	ethernet = struct.pack("!6s6s2s", *(b'\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00\x00\x00', b'\x08\x00'))
	ip = struct.pack("!12s4s4s", *(b'E\x00\x00Mi\x06@\x00@\x11\xd3\x97', b'\x7f\x00\x00\x01', b'\x7f\x00\x00\x01'))

	#proto = 17 # 6 == tcp, 17 == udp
	proto = socket.IPPROTO_UDP
	message = bytes(message, 'UTF-8')
	addr = bytes(addr, 'UTF-8')

	sum = 0
	sum += checksum(message)
	sum += checksum(addr)
	sum += proto + len(message)

	while sum >> 16:
		sum = (sum & 0xFFFF)+(sum >> 16)

	sum = ~sum
	sum = sum >> 8 # Could also be "sum & 0xFF" - not quite sure https://gist.github.com/fxlv/81209bbd150abfeaceb1f85ff076c9f3

	udp = struct.pack("!2s2s2s2s", *(bin_int(randint(3000, 6000)), bin_int(5554), bin_int(len(message)), bin_int(sum)) )

	return ethernet + ip + udp + message, int(binascii.hexlify(bin_int(sum)), 16)

def parse_packet(frame, addr, core):
	with open('debug.log', 'a') as log:

		ethernet = frame[0:14]
		ethernet_segments = struct.unpack("!6s6s2s", ethernet)

		mac_source, mac_dest = (binascii.hexlify(mac) for mac in ethernet_segments[:2])

		if len(frame) >= 34:
			ip = frame[14:34]

			ip_segments = struct.unpack("!12s4s4s", ip)
			ip_source, ip_dest = (socket.inet_ntoa(section) for section in ip_segments[1:3])

			if ip_dest != '127.0.0.1':
				# We only care about 127.0.0.1
				return ''

			if len(frame) >= 42:
				udp = frame[34:42]

				udp_header = struct.unpack("!2s2s2s2s", udp)
				udp_sourcePort, udp_destPort, udp_length, udp_checksum = [int(binascii.hexlify(x), 16) for x in udp_header[:4]]

				if udp_destPort != 5554:
					return ''

				#core['main_screen'].addstr(core['height']-5, 0, 'Inbound checksum: ' + str(udp_checksum), core['colors']['red'] | curses.A_REVERSE)

				if udp_checksum in core['data_cache']['replays']:
					# Replay attack (Or recieved on multiple interfaces)
					# TODO: Identical messages will get the same checksum. So either we allow duplicate messages or not.
					return ''

				# We'll keep 10 checksums in memory and add trailing checkums to check.
				core['data_cache']['replays'] = core['data_cache']['replays'][-10:]+[udp_checksum]

				log.write(str(frame[:14]) + ' :: ' + str(frame[14:34]) + '\n\n')
				#log.write(str(udp_destPort) + ' = ' + str([frame[42:42+udp_length]]) + '\n')
				data = frame[42:42+udp_length]

				return data.decode('UTF-8')

				#return str(ip_source)+':'+str(udp_sourcePort) + '>' + str(ip_dest) +':'+ str(udp_destPort) + '(len:'+str(udp_length)+')'


		#tcp = frame[34:54]
		#tcp_segments = struct.unpack("!2s2s16s", tcp)

		#print('MAC Source:', b':'.join(mac_source[i:i+2] for i in range(0, len(mac_source), 2)))
		#print('MAC Dest:', b':'.join(mac_dest[i:i+2] for i in range(0, len(mac_dest), 2)))
		#print('IP Source:', ip_source)
		#print('IP Dest:', ip_dest)

			return ''
			#return str(ip_source) + '>' + str(ip_dest)
	return ''

## This is a ctype structure that matches the
## requirements to set a socket in promisc mode.
## In all honesty don't know where i found the values :)
class ifreq(ctypes.Structure):
        _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                    ("ifr_flags", ctypes.c_short)]

class promisc():
	def __init__(self, s, interface=b'lo'):
		self.s = s
		self.interface = interface
		self.ifr = ifreq()

	def on(self):
		## -- Set up promisc mode:
		##

		IFF_PROMISC = 0x100
		SIOCGIFFLAGS = 0x8913
		SIOCSIFFLAGS = 0x8914

		self.ifr.ifr_ifrn = self.interface

		fcntl.ioctl(self.s.fileno(), SIOCGIFFLAGS, self.ifr)
		self.ifr.ifr_flags |= IFF_PROMISC

		fcntl.ioctl(self.s.fileno(), SIOCSIFFLAGS, self.ifr)
		## ------------- DONE

	def off(self):
		## Turn promisc mode off:
		IFF_PROMISC = 0x100
		SIOCSIFFLAGS = 0x8914
		self.ifr.ifr_flags &= ~IFF_PROMISC
		fcntl.ioctl(self.s.fileno(), SIOCSIFFLAGS, self.ifr)
		## ------------- DONE

def terminate(screen):
	curses.nocbreak()
	screen.keypad(False)
	curses.echo()
	curses.endwin()

def setup(screen):
	curses.start_color() # Must be first, right after initscr()
	curses.noecho() # Do not print keystrokes
	curses.cbreak() # React emediately to keystrokes
	screen.keypad(True) # For left/right arrows, we need this

def generate_color_palette():
	colorlist = (("red", curses.COLOR_RED), 
			("green", curses.COLOR_GREEN),
			("yellow", curses.COLOR_YELLOW),
			("blue", curses.COLOR_BLUE),
			("cyan", curses.COLOR_CYAN),
			("magenta", curses.COLOR_MAGENTA),
			("black", curses.COLOR_BLACK),
			("white", curses.COLOR_WHITE))
	colorpairs = 0
	colors = {}
	for name,i in colorlist:
		colorpairs += 1 
		curses.init_pair(colorpairs, i, curses.COLOR_BLACK)
		colors[name]=curses.color_pair(i)
	return colors

signal.signal(signal.SIGINT, sig_handler)
dimensions = shutil.get_terminal_size((80, 20))
screen = curses.initscr()
setup(screen)

core = {}
core['main_screen'] = screen
core['cursor'] = {'pos' : (0, 0)}
#core['data'] = socket(AF_INET, SOCK_DGRAM)
#core['data'].setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
#core['data'].setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
#core['data'].setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
#core['data'].setsockopt(SOL_SOCKET, 25, b'lo\0')
#core['data'].bind(('255.255.255.255', 5554))
core['data'] = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
#core['data'].setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

core['data_cache'] = {'replays' : []}
promisciousMode = promisc(core['data'], b'lo')
promisciousMode.on()

messages = odict()

core['messages'] = messages
core['height'] = dimensions.lines -1
core['width'] = dimensions.columns
core['begin_x'] = 20
core['begin_y'] = 7
core['colors'] = generate_color_palette()

win = curses.newwin(core['height'], core['width'], core['begin_y'], core['begin_x'])

#screen.addstr(core['height']-3, 0, str(core['height']) + 'x' + str(core['width']), core['colors']['magenta'] | curses.A_REVERSE)
#screen.addstr(core['height']-2, 0, str(dimensions.lines) + 'x' + str(dimensions.columns), curses.A_REVERSE)

screen.addstr(core['height'], 0, ' '*(core['width']-1), core['colors']['magenta'] | curses.A_REVERSE)
screen.refresh()

inp = ''

class messageQueue(Thread):
	def __init__(self, messages, core):
		Thread.__init__(self)
		self.messages = messages
		self.pos = 0
		self.core = core
		self.start()

	def send(self, msg):

		message, checksum = struct_frame(msg) # Converts to bytes
		#self.core['main_screen'].addstr(core['height']-4, 0, 'Outbound checksum: ' + str(checksum), core['colors']['blue'] | curses.A_REVERSE)
		core['data_cache']['replays'] = core['data_cache']['replays'][-10:]+[checksum]

		# We add our own checksum to the replay stack before sending it out, because we'll get it back.hej

		test = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
		test.bind(('lo', 0))
		test.send(message)
		test.close()

		#self.core['data'].send(message) #, ('', 5554))

	def run(self):
		mt = None
		for t in t_enum():
			if t.name == 'MainThread':
				mt = t
				break

		pos = 0
		while mt and mt.isAlive():
			frame, addr = self.core['data'].recvfrom(65565)
			message = parse_packet(frame, frame, self.core)
			#with open('debug.log', 'a') as log:
			#	log.write(str([message]))

			if len(message) <= 0:
				continue

			self.core['messages'][len(self.core['messages'])] = {'inbound' : message}
			sleep(0.25)

class message_board(Thread):
	def __init__(self, messages, screen, core):
		Thread.__init__(self)
		self.messages = messages
		self.screen = screen
		self.core = core
		self.start()

	def run(self):
		mt = None
		for t in t_enum():
			if t.name == 'MainThread':
				mt = t
				break

		while mt and mt.isAlive():
			sleep(0.25)
			y = 0
			for msgid, msg in self.messages.items():
				if 'inbound' in msg:
					self.screen.addstr(y, 0, msg['inbound'], curses.A_REVERSE)
				else:
					self.screen.addstr(y, 0, msg['outbound'], self.core['colors']['cyan'] | curses.A_REVERSE)
				y += 1

			curses.setsyx(self.core['cursor']['pos'][0], self.core['cursor']['pos'][1]-1)
			self.screen.addstr(self.core['cursor']['pos'][0], self.core['cursor']['pos'][1], '', self.core['colors']['magenta'] | curses.A_REVERSE)
			self.screen.refresh()

message_board(messages, screen, core)
queue = messageQueue(messages, core)

while 1:
	char = screen.getkey()
	screen.addstr(core['height']-1, 0, str([char]), core['colors']['red'] | curses.A_REVERSE)

	if char == '\x1b':
		break
	elif char == 'KEY_BACKSPACE':
		screen.addstr(core['height'], max(0, len(inp)-1), ' ', core['colors']['magenta'] | curses.A_REVERSE)
		inp = inp[:-1]
		char = ''
	elif char == '\n':
		queue.send(inp)
		messages[len(messages)] = {'outbound' : inp}
		char = ''
		inp = ''
		screen.addstr(core['height'], 0, ' '*(core['width']-1), core['colors']['magenta'] | curses.A_REVERSE)
	inp += char

	screen.addstr(core['height'], 0, inp[0-(core['width']-1):], core['colors']['magenta'] | curses.A_REVERSE)

	core['cursor']['pos'] = (core['height'], len(inp))
	curses.setsyx(core['cursor']['pos'][0], core['cursor']['pos'][1])

	#screen.refresh()

# curses.resizeterm(lines, cols)

#https://docs.python.org/2/howto/curses.html

#while len(t_enum()) >= 1:
#	pass
terminate(screen)
