## Bfdpie

[![PyPI](https://img.shields.io/pypi/v/bfdpie.svg?style=flat)](https://pypi.python.org/pypi/streampie/)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)

Bfdpie is a tiny wrapper library around [binutils](https://www.gnu.org/software/binutils/) (more precisely, `libbfd`). The project draws code and concepts from [pybfd](https://github.com/Groundworkstech/pybfd).

### Installing
To install `bfdpie`, use
```bash
pip install bfdpie
```

### Description

The `libbfd` is a complex beast, and `bfdpie` only exposes the binary loading and disassembling parts of it. The goal of this library is to provide a simple and clean means of loading and disassembling various binary formats, the likes of which are often encountered in CTF challanges. For example, we can print all the symbols of any binary file that `libbfd` supports by simply doing:

```python
>>> from bfdpie import *
>>> b = Binary("/bin/ls")
>>> print b
Binary<'/bin/ls', 'mach', Arch<name:X86_64, bits:64, little_endian:1>>

>>> print b.symbols
{
   '_strlen': Symbol<_strlen, 0x0>, 
   '__DATA.__got': Section<__DATA.__got, 0x5000>, 
   '__TEXT.__stub_helper': Section<__TEXT.__stub_helper, 0x45f8>, 
   ...
}   

>>> text_section = b.symbols[".text"]
>>> print text_section
Section<.text, 0xe94>

>>> print hex(text_section.vma)
0xe94

>>> print b.symbols["_strlen"]
Symbol<_strlen, 0x0>
```

The `b.symbols` holds all the symbols the file has. If we need to know precisely where the symbols come from, we can access the different kinds through
`b.static_symbols`, `b.dynamic_symbols`, `b.synthetic_symbols` and `b.relocs`.

Using the `disassembler` is equally easy.

```python
>>> b = Binary()
>>> dis = b.disassemble_simple(
...    "\xba\x00\x04\x00\x00" +
...    "\x48\x89\xc6" +
...    "\xbf\x00\x00\x00\x00" +
...    "\xb8\x00\x00\x00\x00",
...    ARCH_X86_64
... )
mov edx,0x400
mov rsi,rax
mov edi,0x0
mov eax,0x0
```

Adding new architectures is easy, as long as `binutils` supports them. Currently, the following architectures are supported
```python
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
]
```

```python
>>> b.disassemble_simple(
...    "\xe3\x40\xf1\x10\x00\x04" +
...    "\xeb\xcf\xf1\x00\x00\x04" +
...    "\x07\xf4" +
...    "\x07\x07",
...    ARCH_S390X
... )
lg %r4,272(%r15)
lmg %r12,%r15,256(%r15)
br %r4
nopr %r7
```

