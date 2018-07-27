import unittest
from bfdpie import *

class Test(unittest.TestCase):
   def test_large_vma(self):
      b = Binary()

      b.disassemble(b"\x90", ARCH_I686, 0x80000000)
      b.disassemble(b"\x90", ARCH_X86_64, 0x80000000)

   def test_arch_i686(self):
      # 8048579:   89 e5                   mov    %esp,%ebp
      # 804857b:   53                      push   %ebx
      # 804857c:   bb 4c 96 04 08          mov    $0x804964c,%ebx
      # 8048581:   52                      push   %edx

      b = Binary()
      dis = b.disassemble(
         b"\x89\xe5" +
         b"\x53" +
         b"\xbb\x4c\x96\x04\x08" +
         b"\x52"
         ,arch=ARCH_I686
      )

      self.assertTrue(str(dis[0]) == "mov ebp,esp")
      self.assertTrue(str(dis[1]) == "push ebx")
      self.assertTrue(str(dis[2]) == "mov ebx,0x804964c")
      self.assertTrue(str(dis[3]) == "push edx")

   def test_arch_x86_64(self):
      #  4006aa:   ba 00 04 00 00          mov    $0x400,%edx
      #  4006af:   48 89 c6                mov    %rax,%rsi
      #  4006b2:   bf 00 00 00 00          mov    $0x0,%edi
      #  4006b7:   b8 00 00 00 00          mov    $0x0,%eax

      b = Binary()
      dis = b.disassemble(
         b"\xba\x00\x04\x00\x00" +
         b"\x48\x89\xc6" +
         b"\xbf\x00\x00\x00\x00" +
         b"\xb8\x00\x00\x00\x00",
         ARCH_X86_64
      )

      self.assertTrue(str(dis[0]) == "mov edx,0x400")
      self.assertTrue(str(dis[1]) == "mov rsi,rax")
      self.assertTrue(str(dis[2]) == "mov edi,0x0")
      self.assertTrue(str(dis[3]) == "mov eax,0x0")

   def test_arch_armel(self):
      #    84c0:   e92d4800    push  {fp, lr}
      #    84c4:   e28db004    add   fp, sp, #4
      #    84c8:   e24dd020    sub   sp, sp, #32
      #    84cc:   e24b3024    sub   r3, fp, #36   ; 0x24

      b = Binary()
      dis = b.disassemble(
         b"\x00\x48\x2d\xe9" +
         b"\x04\xb0\x8d\xe2" +
         b"\x20\xd0\x4d\xe2" +
         b"\x24\x30\x4b\xe2",
         ARCH_ARMEL
      )

      self.assertTrue(str(dis[0]) == "push {fp, lr}")
      self.assertTrue(str(dis[1]) == "add fp, sp, #4")
      self.assertTrue(str(dis[2]) == "sub sp, sp, #32")
      self.assertTrue(str(dis[3]) == "sub r3, fp, #36 ; 0x24")

   def test_arch_armel_thumb(self):
      #    84ce:   db00         lsls   r3, r3, #3
      #    84d0:   0020         movs   r0, #0
      #    84d2:   111c         adds   r1, r2, #0
      #    84d4:   1a1c         adds   r2, r3, #0

      b = Binary()
      dis = b.disassemble(
         b"\xdb\x00" +
         b"\x00\x20" +
         b"\x11\x1c" +
         b"\x1a\x1c",
         ARCH_ARMEL_THUMB
      )

      self.assertTrue(str(dis[0]) == "lsls r3, r3, #3")
      self.assertTrue(str(dis[1]) == "movs r0, #0")
      self.assertTrue(str(dis[2]) == "adds r1, r2, #0")
      self.assertTrue(str(dis[3]) == "adds r2, r3, #0")

   def test_arch_armeb(self):
      #    84c0:   e92d4800    push  {fp, lr}
      #    84c4:   e28db004    add   fp, sp, #4
      #    84c8:   e24dd020    sub   sp, sp, #32
      #    84cc:   e24b3024    sub   r3, fp, #36   ; 0x24

      b = Binary()
      dis = b.disassemble(
         b"\xe9\x2d\x48\x00" +
         b"\xe2\x8d\xb0\x04" +
         b"\xe2\x4d\xd0\x20" +
         b"\xe2\x4b\x30\x24",
         ARCH_ARMEB
      )

      self.assertTrue(str(dis[0]) == "push {fp, lr}")
      self.assertTrue(str(dis[1]) == "add fp, sp, #4")
      self.assertTrue(str(dis[2]) == "sub sp, sp, #32")
      self.assertTrue(str(dis[3]) == "sub r3, fp, #36 ; 0x24")

   def test_arch_armeb_thumb(self):
      #    84ce:   00db         lsls   r3, r3, #3
      #    84d0:   2000         movs   r0, #0
      #    84d2:   1c11         adds   r1, r2, #0
      #    84d4:   1c1a         adds   r2, r3, #0

      b = Binary()
      dis = b.disassemble(
         b"\x00\xdb" +
         b"\x20\x00" +
         b"\x1c\x11" +
         b"\x1c\x1a",
         ARCH_ARMEB_THUMB
      )

      self.assertTrue(str(dis[0]) == "lsls r3, r3, #3")
      self.assertTrue(str(dis[1]) == "movs r0, #0")
      self.assertTrue(str(dis[2]) == "adds r1, r2, #0")
      self.assertTrue(str(dis[3]) == "adds r2, r3, #0")

   def test_arch_mips(self):
      #  4009d8:   8fbf001c    lw      ra,28(sp)
      #  4009dc:   00000000    nop
      #  4009e0:   03e00008    jr      ra
      #  4009e4:   27bd0020    addiu   sp,sp,32

      b = Binary()
      dis = b.disassemble(
         b"\x8f\xbf\x00\x1c" +
         b"\x00\x00\x00\x00" +
         b"\x03\xe0\x00\x08" +
         b"\x27\xbd\x00\x20",
         ARCH_MIPS
      )

      self.assertTrue(str(dis[0]) == "lw ra,28(sp)")
      self.assertTrue(str(dis[1]) == "nop")
      self.assertTrue(str(dis[2]) == "jr ra")
      self.assertTrue(str(dis[3]) == "addiu sp,sp,32")

   def test_arch_mipsel(self):
      #  4009d8:   1c00bf8f    lw      ra,28(sp)
      #  4009dc:   00000000    nop
      #  4009e0:   0800e003    jr      ra
      #  4009e4:   2000bd27    addiu   sp,sp,32

      b = Binary()
      dis = b.disassemble(
         b"\x1c\x00\xbf\x8f" +
         b"\x00\x00\x00\x00" +
         b"\x08\x00\xe0\x03" +
         b"\x20\x00\xbd\x27",
         ARCH_MIPSEL
      )

      self.assertTrue(str(dis[0]) == "lw ra,28(sp)")
      self.assertTrue(str(dis[1]) == "nop")
      self.assertTrue(str(dis[2]) == "jr ra")
      self.assertTrue(str(dis[3]) == "addiu sp,sp,32")

   def test_arch_mips64(self):
      #   120000918:   3c1c0002    lui   gp,0x2
      #   12000091c:   279c843c    addiu   gp,gp,-31684
      #   120000920:   039fe02d    daddu   gp,gp,ra
      #   120000924:   df998068    ld   t9,-32664(gp)

      b = Binary()
      dis = b.disassemble(
         b"\x3c\x1c\x00\x02" +
         b"\x27\x9c\x84\x3c" +
         b"\x03\x9f\xe0\x2d" +
         b"\xdf\x99\x80\x68",
         ARCH_MIPS64
      )

      self.assertTrue(str(dis[0]) == "lui gp,0x2")
      self.assertTrue(str(dis[1]) == "addiu gp,gp,-31684")
      self.assertTrue(str(dis[2]) == "daddu gp,gp,ra")
      self.assertTrue(str(dis[3]) == "ld t9,-32664(gp)")

   def test_arch_mips64el(self):
      #   120000918:   02001c3c    lui     gp,0x2
      #   12000091c:   3c849c27    addiu   gp,gp,-31684
      #   120000920:   2de09f03    daddu   gp,gp,ra
      #   120000924:   688099df    ld      t9,-32664(gp)

      b = Binary()
      dis = b.disassemble(
         b"\x02\x00\x1c\x3c" +
         b"\x3c\x84\x9c\x27" +
         b"\x2d\xe0\x9f\x03" +
         b"\x68\x80\x99\xdf",
         ARCH_MIPS64EL
      )

      self.assertTrue(str(dis[0]) == "lui gp,0x2")
      self.assertTrue(str(dis[1]) == "addiu gp,gp,-31684")
      self.assertTrue(str(dis[2]) == "daddu gp,gp,ra")
      self.assertTrue(str(dis[3]) == "ld t9,-32664(gp)")

   def test_arch_ppc32(self):
      #   1000058c:   80 01 00 14    lwz     r0,20(r1)
      #   10000590:   38 21 00 10    addi    r1,r1,16
      #   10000594:   7c 08 03 a6    mtlr    r0
      #   10000598:   4e 80 00 20    blr

      b = Binary()
      dis = b.disassemble(
         b"\x80\x01\x00\x14" +
         b"\x38\x21\x00\x10" +
         b"\x7c\x08\x03\xa6" +
         b"\x4e\x80\x00\x20",
         ARCH_PPC32
      )

      self.assertTrue(str(dis[0]) == "lwz r0,20(r1)")
      self.assertTrue(str(dis[1]) == "addi r1,r1,16")
      self.assertTrue(str(dis[2]) == "mtlr r0")
      self.assertTrue(str(dis[3]) == "blr")

   def test_arch_ppc64(self):
      #    100007d4:   38 21 00 70    addi    r1,r1,112
      #    100007d8:   e8 01 00 10    ld      r0,16(r1)
      #    100007dc:   7c 08 03 a6    mtlr    r0
      #    100007e0:   4e 80 00 20    blr

      b = Binary()
      dis = b.disassemble(
         b"\x38\x21\x00\x70" +
         b"\xe8\x01\x00\x10" +
         b"\x7c\x08\x03\xa6" +
         b"\x4e\x80\x00\x20",
         ARCH_PPC64
      )

      self.assertTrue(str(dis[0]) == "addi r1,r1,112")
      self.assertTrue(str(dis[1]) == "ld r0,16(r1)")
      self.assertTrue(str(dis[2]) == "mtlr r0")
      self.assertTrue(str(dis[3]) == "blr")

   def test_arch_sparc(self):
      #   105e4:   9d e3 bf 98    save  %sp, -104, %sp
      #   105ec:   01 00 00 00    nop
      #   105f0:   81 c7 e0 08    ret
      #   105f4:   81 e8 00 00    restore

      b = Binary()
      dis = b.disassemble(
         b"\x9d\xe3\xbf\x98" +
         b"\x01\x00\x00\x00" +
         b"\x81\xc7\xe0\x08" +
         b"\x81\xe8\x00\x00",
         ARCH_SPARC
      )

      self.assertTrue(str(dis[0]) == "save %sp, -104, %sp")
      self.assertTrue(str(dis[1]) == "nop")
      self.assertTrue(str(dis[2]) == "ret")
      self.assertTrue(str(dis[3]) == "restore")

   def test_arch_sparc64(self):
      #  1007a0:   9f c0 40 00    call  %g1
      #  1007a4:   ba 07 7f f8    add  %i5, -8, %i5
      #  1007a8:   c2 5f 40 00    ldx  [ %i5 ], %g1
      #  1007ac:   80 a0 7f ff    cmp  %g1, -1

      b = Binary()
      dis = b.disassemble(
         b"\x9f\xc0\x40\x00" +
         b"\xba\x07\x7f\xf8" +
         b"\xc2\x5f\x40\x00" +
         b"\x80\xa0\x7f\xff",
         ARCH_SPARC64
      )

      self.assertTrue(str(dis[0]) == "call %g1")
      self.assertTrue(str(dis[1]) == "add %i5, -8, %i5")
      self.assertTrue(str(dis[2]) == "ldx [ %i5 ], %g1")
      self.assertTrue(str(dis[3]) == "cmp %g1, -1")

   def test_arch_sh4(self):
      #  400618:   26 4f          lds.l   @r15+,pr
      #  40061a:   0b 00          rts
      #  40061c:   f6 68          mov.l   @r15+,r8
      #  40061e:   09 00          nop

      b = Binary()
      dis = b.disassemble(
         b"\x26\x4f" +
         b"\x0b\x00" +
         b"\xf6\x68" +
         b"\x09\x00",
         ARCH_SH4
      )

      self.assertTrue(str(dis[0]) == "lds.l @r15+,pr")
      self.assertTrue(str(dis[1]) == "rts")
      self.assertTrue(str(dis[2]) == "mov.l @r15+,r8")
      self.assertTrue(str(dis[3]) == "nop")

   def test_arch_sh4eb(self):
      #  400618:   4f 26         lds.l   @r15+,pr
      #  40061a:   00 0b         rts
      #  40061c:   68 f6         mov.l   @r15+,r8
      #  40061e:   00 09         nop

      b = Binary()
      dis = b.disassemble(
         b"\x4f\x26" +
         b"\x00\x0b" +
         b"\x68\xf6" +
         b"\x00\x09",
         ARCH_SH4EB
      )

      self.assertTrue(str(dis[0]) == "lds.l @r15+,pr")
      self.assertTrue(str(dis[1]) == "rts")
      self.assertTrue(str(dis[2]) == "mov.l @r15+,r8")
      self.assertTrue(str(dis[3]) == "nop")

   def test_arch_aarch64(self):
      #  400624:   a9bf7bfd    stp   x29, x30, [sp,#-16]!
      #  400628:   910003fd    mov   x29, sp
      #  40062c:   a8c17bfd    ldp   x29, x30, [sp],#16
      #  400630:   d65f03c0    ret

      b = Binary()
      dis = b.disassemble(
         b"\xfd\x7b\xbf\xa9" +
         b"\xfd\x03\x00\x91" +
         b"\xfd\x7b\xc1\xa8" +
         b"\xc0\x03\x5f\xd6",
         ARCH_AARCH64
      )

      self.assertTrue(str(dis[0]) == "stp x29, x30, [sp,#-16]!")
      self.assertTrue(str(dis[1]) == "mov x29, sp")
      self.assertTrue(str(dis[2]) == "ldp x29, x30, [sp],#16")
      self.assertTrue(str(dis[3]) == "ret")

   def test_arch_alpha(self):
      #   1200007e8:   3e 15 c2 43    subq  sp,0x10,sp
      #   1200007ec:   00 00 5e b7    stq   ra,0(sp)
      #   1200007f0:   08 00 be b7    stq   gp,8(sp)
      #   1200007f4:   00 00 fe 2f    unop

      b = Binary()
      dis = b.disassemble(
         b"\x3e\x15\xc2\x43" +
         b"\x00\x00\x5e\xb7" +
         b"\x08\x00\xbe\xb7" +
         b"\x00\x00\xfe\x2f",
         ARCH_ALPHA
      )

      self.assertTrue(str(dis[0]) == "subq sp,0x10,sp")
      self.assertTrue(str(dis[1]) == "stq ra,0(sp)")
      self.assertTrue(str(dis[2]) == "stq gp,8(sp)")
      self.assertTrue(str(dis[3]) == "unop")

   def test_arch_crisv32(self):
      #   80610:   6e0e                   move.d [$sp+],$r0
      #   80612:   31b6                   move $r1,$srp
      #   80614:   6e1e                   move.d [$sp+],$r1
      #   80616:   f0b9                   ret

      b = Binary()
      dis = b.disassemble(
         b"\x6e\x0e" +
         b"\x31\xb6" +
         b"\x6e\x1e" +
         b"\xf0\xb9",
         ARCH_CRISV32
      )

      self.assertTrue(str(dis[0]) == "move.d [$sp+],$r0")
      self.assertTrue(str(dis[1]) == "move $r1,$srp")
      self.assertTrue(str(dis[2]) == "move.d [$sp+],$r1")
      self.assertTrue(str(dis[3]) == "ret")

   def test_arch_s390x(self):
      #    80000724:   e3 40 f1 10 00 04    lg    %r4,272(%r15)
      #    8000072a:   eb cf f1 00 00 04    lmg   %r12,%r15,256(%r15)
      #    80000730:   07 f4                br    %r4
      #    80000732:   07 07                nopr  %r7

      b = Binary()
      dis = b.disassemble(
         b"\xe3\x40\xf1\x10\x00\x04" +
         b"\xeb\xcf\xf1\x00\x00\x04" +
         b"\x07\xf4" +
         b"\x07\x07",
         ARCH_S390X
      )

      self.assertTrue(str(dis[0]) == "lg %r4,272(%r15)")
      self.assertTrue(str(dis[1]) == "lmg %r12,%r15,256(%r15)")
      self.assertTrue(str(dis[2]) == "br %r4")
      self.assertTrue(str(dis[3]) == "nopr %r7")

   def test_arch_microblaze(self):
      #  10000628:	3021ffe0 	addik	r1, r1, -32
      #  1000062c:	fa81001c 	swi	r20, r1, 28
      #  10000630:	f9e10000 	swi	r15, r1, 0
      #  10000634:	96808000 	mfs	r20, rpc

      b = Binary()
      dis = b.disassemble(
         b"\x30\x21\xff\xe0" +
         b"\xfa\x81\x00\x1c" +
         b"\xf9\xe1\x00\x00" +
         b"\x96\x80\x80\x00",
         ARCH_MICROBLAZE
      )

      self.assertTrue(str(dis[0]) == "addik r1, r1, -32")
      self.assertTrue(str(dis[1]) == "swi r20, r1, 28")
      self.assertTrue(str(dis[2]) == "swi r15, r1, 0")
      self.assertTrue(str(dis[3]) == "mfs r20, rpc")

   def test_arch_microblazeel(self):
      #  10000628:	e03021ff 	addik	r1, r1, -32
      #  1000062c:	1cfa8100 	swi	r20, r1, 28
      #  10000630:	00f9e100 	swi	r15, r1, 0
      #  10000634:	00968080 	mfs	r20, rpc

      b = Binary()
      dis = b.disassemble(
         b"\xe0\xff\x21\x30" +
         b"\x1c\x00\x81\xfa" +
         b"\x00\x00\xe1\xf9" +
         b"\x00\x80\x80\x96",
         ARCH_MICROBLAZEEL
      )

      self.assertTrue(str(dis[0]) == "addik r1, r1, -32")
      self.assertTrue(str(dis[1]) == "swi r20, r1, 28")
      self.assertTrue(str(dis[2]) == "swi r15, r1, 0")
      self.assertTrue(str(dis[3]) == "mfs r20, rpc")

   def test_loading(self):   
      b = Binary()
      
      self.assertTrue(b.file_type == "elf")
      self.assertTrue(str(b.arch) == "Arch<name:X86_64, bits:64, little_endian:1>")

if __name__ == "__main__":
   unittest.main()

