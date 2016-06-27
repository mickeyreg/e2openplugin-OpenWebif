# -*- coding: utf-8 -*-

##############################################################################
#                        2014 E2OpenPlugins                                  #
#                                                                            #
#  This file is open source software; you can redistribute it and/or modify  #
#     it under the terms of the GNU General Public License version 2 as      #
#               published by the Free Software Foundation.                   #
#                                                                            #
##############################################################################
# Simulate the oe-a boxbranding module (Only functions required by OWIF)     #
##############################################################################

from Plugins.Extensions.OpenWebif.__init__ import _
from Components.About import about
from socket import has_ipv6
from Tools.Directories import fileExists, pathExists
import string
import os, hashlib

try:
	from Components.About import about
except:
	pass

tpmloaded = 1
try:
	from enigma import eTPM
	if not hasattr(eTPM, 'getData'):
		tpmloaded = 0
except:
	tpmloaded = 0

def validate_certificate(cert, key):
	buf = decrypt_block(cert[8:], key)
	if buf is None:
		return None
	return buf[36:107] + cert[139:196]

def get_random():
	try:
		xor = lambda a,b: ''.join(chr(ord(c)^ord(d)) for c,d in zip(a,b*100))
		random = urandom(8)
		x = str(time())[-8:]
		result = xor(random, x)

		return result
	except:
		return None

def bin2long(s):
	return reduce( lambda x,y:(x<<8L)+y, map(ord, s))

def long2bin(l):
	res = ""
	for byte in range(128):
		res += chr((l >> (1024 - (byte + 1) * 8)) & 0xff)
	return res

def rsa_pub1024(src, mod):
	return long2bin(pow(bin2long(src), 65537, bin2long(mod)))

def decrypt_block(src, mod):
	if len(src) != 128 and len(src) != 202:
		return None
	dest = rsa_pub1024(src[:128], mod)
	hash = hashlib.sha1(dest[1:107])
	if len(src) == 202:
		hash.update(src[131:192])
	result = hash.digest()
	if result == dest[107:127]:
		return dest
	return None

def tpm_check():
	try:
		tpm = eTPM()
		rootkey = ['\x9f', '|', '\xe4', 'G', '\xc9', '\xb4', '\xf4', '#', '&', '\xce', '\xb3', '\xfe', '\xda', '\xc9', 'U', '`', '\xd8', '\x8c', 's', 'o', '\x90', '\x9b', '\\', 'b', '\xc0', '\x89', '\xd1', '\x8c', '\x9e', 'J', 'T', '\xc5', 'X', '\xa1', '\xb8', '\x13', '5', 'E', '\x02', '\xc9', '\xb2', '\xe6', 't', '\x89', '\xde', '\xcd', '\x9d', '\x11', '\xdd', '\xc7', '\xf4', '\xe4', '\xe4', '\xbc', '\xdb', '\x9c', '\xea', '}', '\xad', '\xda', 't', 'r', '\x9b', '\xdc', '\xbc', '\x18', '3', '\xe7', '\xaf', '|', '\xae', '\x0c', '\xe3', '\xb5', '\x84', '\x8d', '\r', '\x8d', '\x9d', '2', '\xd0', '\xce', '\xd5', 'q', '\t', '\x84', 'c', '\xa8', ')', '\x99', '\xdc', '<', '"', 'x', '\xe8', '\x87', '\x8f', '\x02', ';', 'S', 'm', '\xd5', '\xf0', '\xa3', '_', '\xb7', 'T', '\t', '\xde', '\xa7', '\xf1', '\xc9', '\xae', '\x8a', '\xd7', '\xd2', '\xcf', '\xb2', '.', '\x13', '\xfb', '\xac', 'j', '\xdf', '\xb1', '\x1d', ':', '?']
		random = None
		result = None
		l2r = False
		l2k = None
		l3k = None

		l2c = tpm.getData(eTPM.DT_LEVEL2_CERT)
		if l2c is None:
			return 0

		l2k = validate_certificate(l2c, rootkey)
		if l2k is None:
			return 0

		l3c = tpm.getData(eTPM.DT_LEVEL3_CERT)
		if l3c is None:
			return 0

		l3k = validate_certificate(l3c, l2k)
		if l3k is None:
			return 0

		random = get_random()
		if random is None:
			return 0

		value = tpm.computeSignature(random)
		result = decrypt_block(value, l3k)
		if result is None:
			return 0

		if result [80:88] != random:
			return 0

		return 1
	except:
		return 0

def getAllInfo():
	info = {}

	brand = "unknown"
	model = "unknown"
	procmodel = "unknown"
	orgdream = 0
	if tpmloaded:
		orgdream = tpm_check()
	
	if fileExists("/proc/boxtype"):
		f = open("/proc/boxtype",'r')
		procmodel = f.readline().strip().lower()
		f.close()
		if procmodel in ("adb2850", "adb2849", "bska", "bsla", "bxzb", "bzzb"):
			brand = "Advanced Digital Broadcast"
			if procmodel in ("bska", "bxzb"):
				model = "ADB 5800S"
			elif procmodel in ("bsla", "bzzb"):
				model = "ADB 5800SX"
			elif procmodel == "adb2849":
				model = "ADB 2849ST"
			else:
				model = "ADB 2850ST"
		elif procmodel in ("esi88", "uhd88"):
			brand = "Sagemcom"
			if procmodel == "uhd88":
				model = "UHD 88"
			else:
				model = "ESI 88"
	elif fileExists("/proc/stb/info/boxtype"):
		f = open("/proc/stb/info/boxtype",'r')
		procmodel = f.readline().strip().lower()
		f.close()
		if procmodel == "arivalink200":
			brand = "Ferguson"
			model = "Ariva @Link 200"
		elif procmodel.startswith("spark"):
			brand = "Fulan"
			if procmodel == "spark7162":
				model = "Spark 7162"
			else:
				model = "Spark"
	elif fileExists("/proc/stb/info/model"):
		f = open("/proc/stb/info/model",'r')
		procmodel = f.readline().strip().lower()
		f.close()
		if procmodel == "dsi87":
			brand = "Sagemcom"
			model = "DSI 87"
		elif procmodel.startswith("spark"):
			brand = "Fulan"
			if procmodel == "spark7162":
				model = "Spark 7162"
			else:
				model = "Spark"
		else:
			model = procmodel

	type = procmodel
	if type in ("bska", "bxzb"):
		type = "nbox_white"
	elif type in ("bsla", "bzzb"):
		type = "nbox"
	elif type == "sagemcom88":
		type = "esi88"

	info['brand'] = brand
	info['model'] = model
	info['procmodel'] = procmodel
	info['type'] = type

	remote = "dmm"
	if procmodel.startswith("spark"):
		remote = "spark"
	elif procmodel in ("adb2850", "adb2849", "bska", "bsla", "bxzb", "bzzb", "esi88", "uhd88", "dsi87", "arivalink200"):
		remote = "nbox"

	info['remote'] = remote

	kernel = about.getKernelVersionString()[0]

	distro = "unknown"
	imagever = "unknown"
	imagebuild = ""
	driverdate = "unknown"

	# Assume OE 1.6
	oever = "OE 1.6"
	if kernel>2:
		oever = "OE 2.0"

	if fileExists("/var/grun/grcstype"):
		distro = "Graterlia OS"
		try:
			imagever = about.getImageVersionString()
		except:
			pass
	# ToDo: If your distro gets detected as OpenPLi, feel free to add a detection for your distro here ...
	else:
		try:
			imagever = about.getImageVersionString()
		except:
			pass


	# reporting the installed dvb-module version is as close as we get without too much hassle
	driverdate = 'unknown'
	try:
		driverdate = os.popen('/usr/bin/opkg -V0 list_installed *kernel-core-default-gos*').readline().split( )[2]
	except:
		pass

	info['oever'] = oever
	info['distro'] = distro
	info['imagever'] = imagever
	info['imagebuild'] = imagebuild
	info['driverdate'] = driverdate

	return info

STATIC_INFO_DIC = getAllInfo()

def getMachineBuild():
	return STATIC_INFO_DIC['procmodel']

def getMachineBrand():
	return STATIC_INFO_DIC['brand']

def getMachineName():
	return STATIC_INFO_DIC['model']

def getMachineProcModel():
	return STATIC_INFO_DIC['procmodel']

def getBoxType():
	return STATIC_INFO_DIC['type']

def getOEVersion():
	return STATIC_INFO_DIC['oever']

def getDriverDate():
	return STATIC_INFO_DIC['driverdate']

def getImageVersion():
	return STATIC_INFO_DIC['imagever']

def getImageBuild():
	return STATIC_INFO_DIC['imagebuild']

def getImageDistro():
	return STATIC_INFO_DIC['distro']

class rc_model:
	def getRcFolder(self):
		return STATIC_INFO_DIC['remote']
