# -*- coding: utf-8 -*-

import os
import re
from . import _bfdpie as _bfd

PATH = os.path.dirname(os.path.realpath(__file__))

# libbfd section flags
SEC_NO_FLAGS      = 0x000
SEC_ALLOC         = 0x001 # Tells the OS to allocate space for this section when loading. This is clear for a section containing debug information only.
SEC_LOAD          = 0x002 # Tells the OS to load the section from the file when loading. This is clear for a .bss section.
SEC_RELOC         = 0x004 # The section contains data still to be relocated, so there is some relocation information too.
SEC_READONLY      = 0x008 # A signal to the OS that the section contains read only data.
SEC_CODE          = 0x010 # The section contains code only.
SEC_DATA          = 0x020 # The section contains data only.
SEC_ROM           = 0x040 # The section will reside in ROM.
SEC_HAS_CONTENTS  = 0x100 # The section has contents

# libbfd flavours
file_types = [
   "unknown",
   "aout",
   "coff",
   "ecoff",
   "xcoff",
   "elf",
   "ieee",
   "nlm",
   "oasys",
   "tekhex",
   "srec",
   "verilog",
   "ihex",
   "som",
   "os9k",
   "versados",
   "msdos",
   "ovax",
   "evax",
   "mmo",
   "mach",
   "pef",
   "pef",
   "sym",
]

class Arch():
   def __init__(self, name, bfd_name, bits, little_endian):
      self.name = name
      self.bfd_name = bfd_name
      self.bits = bits
      self.little_endian = little_endian

   def __repr__(self):
      return "Arch<name:%s, bits:%d, little_endian:%s>" % (self.name, self.bits, self.little_endian)

   def __eq__(self, other):
      return self.name == other.name and self.bits == other.bits and self.little_endian == other.little_endian

   def __hash__(self):
      return hash((self.name, self.bits, self.little_endian))

ARCH_I686 = Arch(name="I686", bfd_name="i386", bits=32, little_endian=1)
ARCH_X86_64 = Arch(name="X86_64", bfd_name="i386", bits=64, little_endian=1)

ARCH_AARCH64 = Arch(name="AARCH64", bfd_name="aarch64", bits=64, little_endian=1)
ARCH_AARCH64_BE = Arch(name="AARCH64_BE", bfd_name="aarch64", bits=64, little_endian=0)

ARCH_ARMEL = Arch(name="ARMEL", bfd_name="arm", bits=32, little_endian=1)
ARCH_ARMEB = Arch(name="ARMEB", bfd_name="arm", bits=32, little_endian=0)

ARCH_ARMEL_THUMB = Arch(name="ARMEL_THUMB", bfd_name="arm", bits=32, little_endian=1)
ARCH_ARMEB_THUMB = Arch(name="ARMEB_THUMB", bfd_name="arm", bits=32, little_endian=0)

ARCH_ALPHA = Arch(name="ALPHA", bfd_name="alpha", bits=64, little_endian=1)
ARCH_CRISV32 = Arch(name="CRISV32", bfd_name="cris", bits=32, little_endian=1)

ARCH_MIPSEL = Arch(name="MIPSEL", bfd_name="mips", bits=32, little_endian=1)
ARCH_MIPS = Arch(name="MIPS", bfd_name="mips", bits=32, little_endian=0)

ARCH_MIPS64EL = Arch(name="MIPS64EL", bfd_name="mips", bits=64, little_endian=1)
ARCH_MIPS64 = Arch(name="MIPS64", bfd_name="mips", bits=64, little_endian=0)

ARCH_PPC32 = Arch(name="PPC32", bfd_name="powerpc", bits=32, little_endian=0)
ARCH_PPC64 = Arch(name="PPC64", bfd_name="powerpc", bits=64, little_endian=0)

ARCH_S390X = Arch(name="S390X", bfd_name="s390", bits=64, little_endian=0)

ARCH_SH4 = Arch(name="SH4", bfd_name="sh", bits=32, little_endian=1)
ARCH_SH4EB = Arch(name="SH4EB", bfd_name="sh", bits=32, little_endian=0)

ARCH_SPARC = Arch(name="SPARC", bfd_name="sparc", bits=32, little_endian=0)
ARCH_SPARC64 = Arch(name="SPARC64", bfd_name="sparc", bits=32, little_endian=0)

ARCH_MICROBLAZE = Arch(name="MICROBLAZE", bfd_name="MicroBlaze", bits=32, little_endian=0)
ARCH_MICROBLAZEEL = Arch(name="MICROBLAZEEL", bfd_name="MicroBlaze", bits=32, little_endian=1)

archs = [
   ARCH_I686,
   ARCH_X86_64,
   ARCH_ARMEL,
   ARCH_ARMEL_THUMB,
   ARCH_ARMEB,
   ARCH_ARMEB_THUMB,
   ARCH_AARCH64,
   ARCH_AARCH64_BE,
   ARCH_MIPS,
   ARCH_MIPSEL,
   ARCH_MIPS64,
   ARCH_MIPS64EL,
   ARCH_PPC32,
   ARCH_PPC64,
   ARCH_SPARC,
   ARCH_SPARC64,
   ARCH_SH4,
   ARCH_SH4EB,
   ARCH_ALPHA,
   ARCH_CRISV32,
   ARCH_S390X,
   ARCH_MICROBLAZE,
   ARCH_MICROBLAZEEL,
]

class Symbol():
   def __init__(self, index, name, vma, flags):
      self.index = index
      self.name = name
      self.vma = vma
      self.flags = flags

   def __repr__(self):
      return "Symbol<%s, 0x%0x>" % (self.name, self.vma)

class Reloc(Symbol):
   pass
   
class Synthetic(Symbol):
   pass

class Section():
   def __init__(self, ptr, index, name, size, vma, lma, alignment_power, flags, filepos, contents):
      self.ptr = ptr
      self.index = index
      self.name = name
      self.size = size
      self.vma = vma
      self.lma = lma
      self.alignment_power = alignment_power
      self.flags = flags
      self.filepos = filepos
      self.contents = contents

   def __repr__(self):
      return "Section<%s, 0x%0x>" % (self.name, self.vma)

class Instruction():
   def __init__(self, opcode, mnemonic, vma, size):
      self.opcode = opcode
      self.mnemonic = mnemonic
      self.vma = vma
      self.size = size

   def __str__(self):
      return "%s" % (self.mnemonic)

   def __repr__(self):
      return str(self)

class BinaryError(Exception):
   pass

class Binary():
   def __init__(self, fname=None):
      self._ptr = None

      self.arch = None
      self.file_type = None
  
      self.sections = {}
      self.static_symbols = {}
      self.dynamic_symbols = {}
      self.synthetic_symbols = {}
      self.relocs = {}
      self.symbols = {}

      self.dynamic_symbols = {}
      if not fname:
         # Fname always needs to point to a valid binary. If none specified, use the dummy one in PATH/bin/dummy.elf
         self.fname = '%s/bin/dummy.elf' % (PATH)
      else:
         self.fname = fname

      self._get_architecture()

      # Extract all the various symbols, ignore errors
      self._get_sections()
        
      try: self._get_static_symbols()
      except: pass

      try: self._get_dynamic_symbols()
      except: pass

      try: self._get_synthetic_symbols()
      except: pass

      try: self._get_relocs()
      except: pass

      # For convenience, merge all dicts into a single symbols dict
      self.symbols.update(self.sections)
      self.symbols.update(self.static_symbols)
      self.symbols.update(self.dynamic_symbols)
      self.symbols.update(self.synthetic_symbols)
      self.symbols.update(self.relocs)

   def _get_architecture(self):
      """
         Fetch various information about the architecture.
      """
      self._openr()
      ret = _bfd.get_architecture(self._ptr)
      self._close()

      self.arch = None
      
      arch_flavour        = ret[0]
      arch_little_endian  = ret[1]
      arch_bits           = ret[2]
      arch_name           = ret[3]
      arch_full_name      = ret[4]

      # Convert BFD architecture designators to our own
      for arch in archs:
         if arch_name.upper() == arch.bfd_name.upper() and arch_little_endian == arch.little_endian and arch_bits == arch.bits:
            # We found a match
            self.arch = arch

      if not self.arch:
         raise BinaryError("Unsupported architecture: %s" % (arch_name))

      # Resolve the type of file
      try:
         self.file_type = file_types[arch_flavour]
      except:
         raise BinaryError("Unknown flavor: " + arch_flavour)

   def _openr(self):
      self._ptr = _bfd.openr(self.fname)

   def _close(self):
      return _bfd.close(self._ptr)

   def _get_relocs(self):
      self._openr()
      relocs = _bfd.get_relocs(self._ptr)
      self._close()

      for reloc in relocs:
         s = Reloc(reloc[0], reloc[1], reloc[2], reloc[3])
         self.relocs[s.name] = s

   def _get_synthetic_symbols(self):
      self._openr()
      synthetics = _bfd.get_synthetic_symbols(self._ptr)
      self._close()

      for synthetic in synthetics:
         s = Synthetic(synthetic[0], synthetic[1], synthetic[2], synthetic[3])
         self.synthetic_symbols[s.name] = s

   def _get_static_symbols(self):
      self._openr()
      symbols =  _bfd.get_static_symbols(self._ptr)
      self._close()

      for symbol in symbols:
         s = Symbol(symbol[0], symbol[1], symbol[2], symbol[3])
         self.static_symbols[s.name] = s

   def _get_dynamic_symbols(self):
      self._openr()
      symbols =  _bfd.get_dynamic_symbols(self._ptr)
      self._close()

      for symbol in symbols:
         s = Symbol(symbol[0], symbol[1], symbol[2], symbol[3])
         self.dynamic_symbols[s.name] = s

   def _get_sections(self):
      self._openr()
      sections = _bfd.get_sections(self._ptr)
      self._close()

      # Split the return list into Section objects
      for s in sections:
         section = Section(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9])
         self.sections[section.name] = section
 
   def disassemble(self, data, arch=None, vma=0):
      if not arch:
         arch = self.arch

      self._openr()
      arch_id = archs.index(arch)
      ops = _bfd.disassemble_bytes(self._ptr, arch_id, data, vma)
      self._close()

      ret = []

      for start_vma, size, mnemonic in ops:
         # In mnemonics, some architectures print tabs, some spaces. Here, we make it all consistent with spaces
         mnemonic = re.sub(r"[\t]+", " ", mnemonic)
         mnemonic = re.sub(r"[  ]+", " ", mnemonic)
         mnemonic = mnemonic.strip()

         data_offset = start_vma - vma
         i = Instruction(data[data_offset:data_offset+size], mnemonic, start_vma, size)
         ret.append(i)

      return ret

   def disassemble_simple(self, data, arch=None, vma=0):
      for i in self.disassemble(data, arch, vma):
         print(i)

   def objcopy(self, ignore=[]):
      ret = ""
      secs = []

      # Sort the sections by LMA, in asscending order and filter
      for sec in sorted(self.sections.itervalues(), key=lambda x:x.lma):
        # Remove sections that shouldn't be loaded
        if sec.flags & SEC_LOAD and sec.flags & SEC_HAS_CONTENTS and sec.name not in ignore:
           secs.append(sec)
         
      for x in range(len(secs) - 1):
         gap_start = secs[x].lma + secs[x].size
         gap_stop = secs[x+1].lma

         # Pad the sections. Based on code from binutils/objcopy.c
         ret += secs[x].contents.ljust(secs[x].size + (gap_stop - gap_start), "\x00")

      # We don't pad the last section, so we just copy it over
      if secs[-1].flags & SEC_LOAD and secs[-1].flags & SEC_HAS_CONTENTS and secs[-1].name not in ignore:
         ret += secs[-1].contents

      # We don't need trailing zeroes
      return ret

   def __repr__(self):
      return "Binary<'%s', '%s', %s>" % (self.fname, self.file_type, self.arch)

