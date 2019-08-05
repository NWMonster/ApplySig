#Apply IDA FLIRT signatures for Ghidra
# original code from
#    https://github.com/thebabush/nampa/blob/b04a506ea83e6ac48c1e13288ce155d97d42922d/nampa/flirt.py
#    https://github.com/radare/radare2/blob/0948f9536b20be553bfbdbf1fc877b80fad3efa0/libr/anal/flirt.c
#@author NWMonster
#@category FunctionID
#@menupath Tools.Function ID.ApplySig

from __future__ import print_function
from ghidra.framework.model import DomainFile
from ghidra.program.model.symbol import SourceType
from ghidra.util import Msg

from java.lang import IllegalArgumentException
try:
	from typing import List
except ImportError:
	pass
from itertools import izip, islice
try:
	from StringIO import StringIO
except ImportError:
	from io import StringIO
import zlib
import struct

#############  binrw lib

def read_x(fmt, f, l):
	return struct.unpack(fmt, f.read(l))[0]


def read_u8(f):
	return read_x('B', f, 1)


def read_u16be(f):
	return read_x('>H', f, 2)


def read_u24be(f):
	return read_u8(f) << 16 | read_u16be(f)


def read_u32be(f):
	return read_x('>L', f, 4)


def read_u16le(f):
	return read_x('<H', f, 2)


def read_u32le(f):
	return read_x('<L', f, 4)


############# crc lib

POLY = 0x1021
_crc_table = []


def _rev8(n):
	return int('{:08b}'.format(n)[::-1], 2)


def _rev16(n):
	return int('{:016b}'.format(n)[::-1], 2)

_poly_rev = _rev16(POLY)


def _init_table():
	for i in range(256):
		i = _rev8(i)

		crc = 0
		c = (i << 8) & 0xFFFF

		for j in range(8):
			if (crc ^ c) & 0x8000:
				crc = (crc << 1) ^ POLY
			else:
				crc = (crc << 1)

			crc &= 0xFFFF
			c = (c << 1) & 0xFFFF

		crc = _rev16(crc)
		_crc_table.append(crc)
_init_table()


def crc16(data, start_value=0xFFFF):
	"""
	Perform CRC16 X.25

	:param data: a list of bytes or a bytearray
	:param start_value: the start value for the CRC. Should be a 16-bits value.
						Should be left to the default value.
	:return: the CRC16-X.25 of the given bytes
	"""
	out = start_value

	for b in data:
		tmp = (out ^ b) & 0xFF
		out = (out >> 8) ^ _crc_table[tmp]

	out ^= 0xFFFF
	out = ((out & 0xFF) << 8) | ((out >> 8) & 0xff)
	return out


def crc16slow(data, start_value=0xFFFF):
	out = start_value

	for b in data:
		for i in range(8):
			if (out ^ b) & 1 == 1:
				out = (out >> 1) ^ _poly_rev
			else:
				out >>= 1
			b >>= 1

	out = (~out) & 0xFFFF
	out = ((out & 0xFF) << 8) | ((out >> 8) & 0xff)
	return out

############# flirt parser

FLIRT_NAME_MAX = 1024

def list2hexstring(ll):
	return ''.join(['{:02X}'.format(l) for l in ll])


def pattern2string(pp, mask_array):
	if pp is None:
		return ''
	return ''.join(['{:02X}'.format(p) if not m else '..' for p, m in zip(pp, mask_array)])


def read_max_2_bytes(f):
	b = read_u8(f)
	if b & 0x80 == 0x80:
		return ((b & 0x7F) << 8) | read_u8(f)
	else:
		return b


def read_multiple_bytes(f):
	b = read_u8(f)
	if b & 0x80 != 0x80:
		return b
	elif b & 0xC0 != 0xC0:
		return ((b & 0x7F) << 8) | read_u8(f)
	elif b & 0xE0 != 0xE0:
		return ((b & 0x3F) << 24) | read_u24be(f)
	else:
		return read_u32be(f)


def read_node_variant_mask(f, length):
	if length < 0x10:
		return read_max_2_bytes(f)
	elif length <= 0x20:
		return read_multiple_bytes(f)
	elif length <= 0x40:
		return (read_multiple_bytes(f) << 32) | read_multiple_bytes(f)
	else:
		raise FlirtException('Wrong node variant mask length: {}'.format(length))


def read_node_bytes(f, length, variant_mask):
	mask_bit = 1 << length - 1
	variant_bools = list()
	pattern = list()
	for i in range(length):
		curr_mask_bool = variant_mask & mask_bit != 0
		if curr_mask_bool:
			pattern.append(0)
		else:
			pattern.append(read_u8(f))
		variant_bools.append(curr_mask_bool)
		mask_bit >>= 1
	return variant_bools, pattern


class FlirtArch(object):
	ARCH_386 = 0          # Intel 80x86
	ARCH_Z80 = 1          # 8085, Z80
	ARCH_I860 = 2         # Intel 860
	ARCH_8051 = 3         # 8051
	ARCH_TMS = 4          # Texas Instruments TMS320C5x
	ARCH_6502 = 5         # 6502
	ARCH_PDP = 6          # PDP11
	ARCH_68K = 7          # Motoroal 680x0
	ARCH_JAVA = 8         # Java
	ARCH_6800 = 9         # Motorola 68xx
	ARCH_ST7 = 10         # SGS-Thomson ST7
	ARCH_MC6812 = 11      # Motorola 68HC12
	ARCH_MIPS = 12        # MIPS
	ARCH_ARM = 13         # Advanced RISC Machines
	ARCH_TMSC6 = 14       # Texas Instruments TMS320C6x
	ARCH_PPC = 15         # PowerPC
	ARCH_80196 = 16       # Intel 80196
	ARCH_Z8 = 17          # Z8
	ARCH_SH = 18          # Renesas (formerly Hitachi) SuperH
	ARCH_NET = 19         # Microsoft Visual Studio.Net
	ARCH_AVR = 20         # Atmel 8-bit RISC processor(s)
	ARCH_H8 = 21          # Hitachi H8/300, H8/2000
	ARCH_PIC = 22         # Microchip's PIC
	ARCH_SPARC = 23       # SPARC
	ARCH_ALPHA = 24       # DEC Alpha
	ARCH_HPPA = 25        # Hewlett-Packard PA-RISC
	ARCH_H8500 = 26       # Hitachi H8/500
	ARCH_TRICORE = 27     # Tasking Tricore
	ARCH_DSP56K = 28      # Motorola DSP5600x
	ARCH_C166 = 29        # Siemens C166 family
	ARCH_ST20 = 30        # SGS-Thomson ST20
	ARCH_IA64 = 31        # Intel Itanium IA64
	ARCH_I960 = 32        # Intel 960
	ARCH_F2MC = 33        # Fujistu F2MC-16
	ARCH_TMS320C54 = 34   # Texas Instruments TMS320C54xx
	ARCH_TMS320C55 = 35   # Texas Instruments TMS320C55xx
	ARCH_TRIMEDIA = 36    # Trimedia
	ARCH_M32R = 37        # Mitsubishi 32bit RISC
	ARCH_NEC_78K0 = 38    # NEC 78K0
	ARCH_NEC_78K0S = 39   # NEC 78K0S
	ARCH_M740 = 40        # Mitsubishi 8bit
	ARCH_M7700 = 41       # Mitsubishi 16bit
	ARCH_ST9 = 42         # ST9+
	ARCH_FR = 43          # Fujitsu FR Family
	ARCH_MC6816 = 44      # Motorola 68HC16
	ARCH_M7900 = 45       # Mitsubishi 7900
	ARCH_TMS320C3 = 46    # Texas Instruments TMS320C3
	ARCH_KR1878 = 47      # Angstrem KR1878
	ARCH_AD218X = 48      # Analog Devices ADSP 218X
	ARCH_OAKDSP = 49      # Atmel OAK DSP
	ARCH_TLCS900 = 50     # Toshiba TLCS-900
	ARCH_C39 = 51         # Rockwell C39
	ARCH_CR16 = 52        # NSC CR16
	ARCH_MN102L00 = 53    # Panasonic MN10200
	ARCH_TMS320C1X = 54   # Texas Instruments TMS320C1x
	ARCH_NEC_V850X = 55   # NEC V850 and V850ES/E1/E2
	ARCH_SCR_ADPT = 56    # Processor module adapter for processor modules written in scripting languages
	ARCH_EBC = 57         # EFI Bytecode
	ARCH_MSP430 = 58      # Texas Instruments MSP430
	ARCH_SPU = 59         # Cell Broadband Engine Synergistic Processor Unit
	ARCH_DALVIK = 60      # Android Dalvik Virtual Machine


class FlirtFileType(object):
	FILE_DOS_EXE_OLD = 0x00000001
	FILE_DOS_COM_OLD = 0x00000002
	FILE_BIN         = 0x00000004
	FILE_DOSDRV      = 0x00000008
	FILE_NE          = 0x00000010
	FILE_INTELHEX    = 0x00000020
	FILE_MOSHEX      = 0x00000040
	FILE_LX          = 0x00000080
	FILE_LE          = 0x00000100
	FILE_NLM         = 0x00000200
	FILE_COFF        = 0x00000400
	FILE_PE          = 0x00000800
	FILE_OMF         = 0x00001000
	FILE_SREC        = 0x00002000
	FILE_ZIP         = 0x00004000
	FILE_OMFLIB      = 0x00008000
	FILE_AR          = 0x00010000
	FILE_LOADER      = 0x00020000
	FILE_ELF         = 0x00040000
	FILE_W32RUN      = 0x00080000
	FILE_AOUT        = 0x00100000
	FILE_PILOT       = 0x00200000
	FILE_DOS_EXE     = 0x00400000
	FILE_DOS_COM     = 0x00800000
	FILE_AIXAR       = 0x01000000


class FlirtOsType(object):
	OS_MSDOS   = 0x01
	OS_WIN     = 0x02
	OS_OS2     = 0x04
	OS_NETWARE = 0x08
	OS_UNIX    = 0x10
	OS_OTHER   = 0x20


class FlirtAppType(object):
	APP_CONSOLE         = 0x0001
	APP_GRAPHICS        = 0x0002
	APP_EXE             = 0x0004
	APP_DLL             = 0x0008
	APP_DRV             = 0x0010
	APP_SINGLE_THREADED = 0x0020
	APP_MULTI_THREADED  = 0x0040
	APP_16_BIT          = 0x0080
	APP_32_BIT          = 0x0100
	APP_64_BIT          = 0x0200


class FlirtFeatureFlag(object):
	FEATURE_STARTUP       = 0x01
	FEATURE_CTYPE_CRC     = 0x02
	FEATURE_2BYTE_CTYPE   = 0x04
	FEATURE_ALT_CTYPE_CRC = 0x08
	FEATURE_COMPRESSED    = 0x10


class FlirtParseFlag(object):
	PARSE_MORE_PUBLIC_NAMES          = 0x01
	PARSE_READ_TAIL_BYTES            = 0x02
	PARSE_READ_REFERENCED_FUNCTIONS  = 0x04
	PARSE_MORE_MODULES_WITH_SAME_CRC = 0x08
	PARSE_MORE_MODULES               = 0x10


class FlirtFunctionFlag(object):
	FUNCTION_LOCAL = 0x02                 # describes a static function
	FUNCTION_UNRESOLVED_COLLISION = 0x08  # describes a collision that wasn't resolved


class FlirtException(Exception):
	pass


class FlirtFunction(object):
	def __init__(self, name, offset, negative_offset, is_local, is_collision):
		self.name = name
		self.offset = offset
		self.negative_offset = negative_offset
		self.is_local = is_local
		self.is_collision = is_collision

	def __str__(self):
		return '<{}: name={}, offset=0x{:04X}, negative_offset={}, is_local={}, is_collision={}>'.format(
			self.__class__.__name__, self.name, self.offset, self.negative_offset, self.is_local, self.is_collision
		)


class FlirtTailByte(object):
	def __init__(self, offset, value):
		self.offset = offset
		self.value = value


class FlirtModule(object):
	def __init__(self, crc_length, crc16, length, public_functions, tail_bytes, referenced_functions):
		# type: (int, int, int, List[FlirtFunction], List[FlirtTailByte], List[FlirtFunction]) -> ()
		self.crc_length = crc_length
		self.crc16 = crc16
		self.length = length
		self.public_functions = public_functions
		self.tail_bytes = tail_bytes
		self.referenced_functions = referenced_functions


class FlirtNode(object):
	def __init__(self, children, modules, length, variant_mask, pattern):
		self.children = children
		self.modules = modules
		self.length = length
		self.variant_mask = variant_mask
		self.pattern = pattern

	@property
	def is_leaf(self):
		return len(self.children) == 0

	def __str__(self):
		return '<{}: children={}, modules={}, length={}, variant={}, pattern="{}">'.format(
			self.__class__.__name__, len(self.children), len(self.modules), self.length, self.variant_mask
			, pattern2string(self.pattern, self.variant_mask)
		)


class FlirtHeader(object):
	def __init__(self, version, arch, file_types, os_types, app_types, features, old_n_functions, crc16, ctype
				 , ctypes_crc16, n_functions, pattern_size, library_name):
		self.version = version
		self.arch = arch
		self.file_types = file_types
		self.os_types = os_types
		self.app_types = app_types
		self.features = features
		self.old_n_functions = old_n_functions
		self.crc16 = crc16
		self.ctype = ctype
		self.ctypes_crc16 = ctypes_crc16
		self.n_functions = n_functions
		self.pattern_size = pattern_size
		self.library_name = library_name


class FlirtFile(object):
	def __init__(self, header, root):
		# type: (FlirtHeader, FlirtNode) -> ()
		self.header = header
		self.root = root


def parse_header(f):
	# type: (file) -> (FlirtHeader)
	magic = f.read(6)
	if magic != b'IDASGN':
		raise FlirtException('Wrong file type')

	version = read_u8(f)
	if version < 5 or version > 10:
		raise FlirtException('Unknown version: {}'.format(version))

	arch = read_u8(f)
	file_types = read_u32le(f)
	os_types = read_u16le(f)
	app_types = read_u16le(f)
	features = read_u16le(f)
	old_n_functions = read_u16le(f)
	crc16 = read_u16le(f)
	ctype = f.read(12)
	library_name_len = read_u8(f)
	ctypes_crc16 = read_u16le(f)

	n_functions = None
	pattern_size = None
	if version >= 6:
		n_functions = read_u32le(f)

		if version >= 8:
			pattern_size = read_u16le(f)

			if version >= 9:
				read_u16le(f) #unknow

	library_name = f.read(library_name_len)

	return FlirtHeader(version, arch, file_types, os_types, app_types, features, old_n_functions, crc16, ctype
					   , ctypes_crc16, n_functions, pattern_size, library_name)


def parse_tail_byte(f, version):
	if version >= 9:
		offset = read_multiple_bytes(f)
	else:
		offset = read_max_2_bytes(f)
	value = read_u8(f)
	return FlirtTailByte(offset, value)


def parse_tail_bytes(f, version):
	if version >= 8:
		length = read_u8(f)
	else:
		length = 1
	tail_bytes = []
	for i in range(length):
		tail_bytes.append(parse_tail_byte(f, version))
	return tail_bytes


def parse_referenced_function(f, version):
	if version >= 9:
		offset = read_multiple_bytes(f)
	else:
		offset = read_max_2_bytes(f)

	name_length = read_u8(f)
	if name_length == 0:
		name_length = read_multiple_bytes(f)

	if name_length & 0x80000000 != 0:  # (int) name_length < 0
		raise FlirtException('Negative name length')

	name = list()
	for i in range(name_length):
		name.append(read_u8(f))

	negative_offset = False
	if name[-1] == 0:
		name = name[:-1]
		negative_offset = True

	name = bytearray(name).decode('ascii')
	return FlirtFunction(name, offset, negative_offset, False, False)


def parse_referenced_functions(f, version):
	if version >= 8:
		length = read_u8(f)
	else:
		length = 1

	referenced_functions = []
	for i in range(length):
		referenced_functions.append(parse_referenced_function(f, version))
	return referenced_functions


def parse_public_function(f, version, offset):
	is_local = False
	is_collision = False

	if version >= 9:
		offset += read_multiple_bytes(f)
	else:
		offset += read_max_2_bytes(f)

	b = read_u8(f)
	if b < 0x20:
		if b & FlirtFunctionFlag.FUNCTION_LOCAL:
			is_local = True
		if b & FlirtFunctionFlag.FUNCTION_UNRESOLVED_COLLISION:
			is_collision = True
		if b & 0x01 or b & 0x04:
			print('Investigate public name flag: 0x{:02X} @ 0x{:04X}'.format(b, offset))
		b = read_u8(f)

	name = list()
	name_finished = False
	for i in range(FLIRT_NAME_MAX):
		if b < 0x20:
			name_finished = True
			break

		name.append(b)
		b = read_u8(f)
	flags = b

	name = bytearray(name).decode('ascii')
	if not name_finished:
		print('Function name too long: {}'.format(name))

	return FlirtFunction(name, offset, False, is_local, is_collision), offset, flags


def parse_module(f, version, crc_length, crc16):
	if version >= 9:
		length = read_multiple_bytes(f)
	else:
		length = read_max_2_bytes(f)
	# assert length < 0x8000    # According to radare2's docs, this should be true, but in my test file it's not :/

	public_fuctions = []
	offset = 0
	while True:
		func, offset, flags = parse_public_function(f, version, offset)
		public_fuctions.append(func)

		if flags & FlirtParseFlag.PARSE_MORE_PUBLIC_NAMES == 0:
			break

	tail_bytes = []
	if flags & FlirtParseFlag.PARSE_READ_TAIL_BYTES != 0:
		tail_bytes = parse_tail_bytes(f, version)

	referenced_functions = []
	if flags & FlirtParseFlag.PARSE_READ_REFERENCED_FUNCTIONS != 0:
		referenced_functions = parse_referenced_functions(f, version)

	return FlirtModule(crc_length, crc16, length, public_fuctions, tail_bytes, referenced_functions), flags


def parse_modules(f, version):
	modules = list()
	while True:
		crc_length = read_u8(f)
		crc16 = read_u16be(f)

		while True:
			module, flags = parse_module(f, version, crc_length, crc16)
			modules.append(module)
			if flags & FlirtParseFlag.PARSE_MORE_MODULES_WITH_SAME_CRC == 0:
				break

		if flags & FlirtParseFlag.PARSE_MORE_MODULES == 0:
			break
	return modules


def parse_tree(f, version, is_root):
	if is_root:
		length = 0
		variant_mask = None
		pattern = None
	else:
		length = read_u8(f)
		variant_mask = read_node_variant_mask(f, length)
		variant_mask, pattern = read_node_bytes(f, length, variant_mask)

	nodes = read_multiple_bytes(f)
	if nodes == 0:
		modules = parse_modules(f, version)
		return FlirtNode([], modules, length, variant_mask, pattern)

	children = list()
	for i in range(nodes):
		children.append(parse_tree(f, version, False))

	return FlirtNode(children, [], length, variant_mask, pattern)


def parse_flirt_file(f):
	# type: (file) -> FlirtFile
	header = parse_header(f)
	if header.features & FlirtFeatureFlag.FEATURE_COMPRESSED:
		if header.version == 5:
			raise FlirtException('Compression in unsupported on flirt v5')
		f = StringIO(zlib.decompress(f.read()))  # Untested

	tree = parse_tree(f, header.version, is_root=True)

	assert len(f.read(1)) == 0  # Have we read all the file?
	return FlirtFile(header, tree)


def match_node_pattern(node, buff, offset):
	# type: (FlirtNode, bytes, int) -> bool
	assert len(buff) - offset >= 0

	# Check if we have enough data
	if len(buff) < offset + len(node.pattern):
		return False
	for i, (b, p, v) in enumerate(izip(islice(buff, offset, len(buff)), node.pattern, node.variant_mask)):
		if b < 0:
			b = b + 256
		if v:
			continue
		elif b != p:
			return False
	return True


# TODO: Write tests
def match_module(module, buff, addr, offset, callback):
	# type: (FlirtModule, bytes, int) -> bool
	buff_size = len(buff) - offset
	if module.crc_length < buff_size and module.crc16 != crc16(buff[offset:offset+module.crc_length]):
		return False

	for tb in module.tail_bytes:
		if module.crc_length + tb.offset < buff_size \
				and buff[offset+module.crc_length+tb.offset] != tb.value:
			return False

	# TODO: referenced functions are not yet implemented in radare2

	for funk in module.public_functions:
		callback(addr, funk)

	return True


def match_node(node, buff, addr, offset, callback):
	if match_node_pattern(node, buff, offset):
		#print('found prefix: {}'.format(pattern2string(node.pattern, node.variant_mask)))
		for child in node.children:
			if match_node(child, buff, addr, offset + node.length, callback):
				return True
		for module in node.modules:
			if match_module(module, buff, addr, offset + node.length, callback):
				return True
	return False


def match_function(sig, buff, addr, callback):
	# type: (FlirtFile, bytes) -> bool
	# assert type(buff) is bytes
	if type(buff) is str:
		buff = bytes(buff)
	for child in sig.root.children:
		if match_node(child, buff, addr, 0, callback):
			return True
	return False

def ask_sig():
	try:
		filepath = askFile("Choose Sig file:", "ApplySig").toString()
		print('Load File:' + filepath)
		return open(filepath, 'rb')
	except IllegalArgumentException as error:
		Msg.warn(self, error.toString())
	except ghidra.util.exception.CancelledException:
		print("User Cancelled")

def get_function_end(funk):
	BBs = funk.getBody().toList()
	max = 0
	for BB in BBs:
		bb_max = int(BB.getMaxAddress().toString(), 16)
		if bb_max > max:
			max = bb_max
	return max

rename_cnt = 0
def funk_rename(addr, funk):
	global rename_cnt
	name = funk.name
	if name != '?':
		funk = getFunctionAt(parseAddress(hex(addr).strip('L')))
		funk.setName(name, SourceType.USER_DEFINED)
		rename_cnt += 1
	return

def apply_sig(flirt):
	funk = getFirstFunction()
	#print(funk.entryPoint
	#print(get_function_end(funk))
	while funk is not None:
		funk_start = int(funk.entryPoint.toString(), 16)
		funk_end   = get_function_end(funk)
		funk_buf   = getBytes(parseAddress(hex(funk_start).strip('L')), funk_end - funk_start + 0x100)
		#print('%x - %x' % (funk_start, funk_end))
		match_function(flirt, funk_buf, funk_start, funk_rename)
		funk = getFunctionAfter(funk)

f = ask_sig()
print('Parse Flirt File.....')
try:
	flirt = parse_flirt_file(f)
except:
	print('Parsing Failed!')
print('Name: ', flirt.header.library_name)
print('Count:', flirt.header.n_functions)
#print('ARCH: ', flirt.header.arch)
#print('OS:   ', flirt.header.os_types)
print('Apply Signatures.....')
apply_sig(flirt)
print('[ %d / %d ]' % (rename_cnt, flirt.header.n_functions))
print('Done!')
