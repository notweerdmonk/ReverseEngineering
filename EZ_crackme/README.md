# EZ crackme

[crackmes.one - EZ crackme](https://crackmes.one/crackme/5fcfb87933c5d424269a1afc)

This is a very easy crackme. Running the binary without arguments results in a crash due to segmentation fault. Using any string as argument prints "Wrong".

```bash
$ ./run.exe aaaaaa
Wrong!
$
```

The file is 32-bit ELF.

```bash
$ file run.exe
run.exe: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, with debug_info, not stripped
```

Examining the sections we get

```bash
$ objdump -h run.exe
Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         00000045  08049000  08049000  00001000  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .data         0000001d  0804a000  0804a000  00002000  2**2
                  CONTENTS, ALLOC, LOAD, DATA
  2 .debug_aranges 00000020  00000000  00000000  0000201d  2**0
                  CONTENTS, READONLY, DEBUGGING, OCTETS
  3 .debug_info   0000003a  00000000  00000000  0000203d  2**0
                  CONTENTS, READONLY, DEBUGGING, OCTETS
  4 .debug_abbrev 0000001b  00000000  00000000  00002077  2**0
                  CONTENTS, READONLY, DEBUGGING, OCTETS
  5 .debug_line   0000004a  00000000  00000000  00002092  2**0
                  CONTENTS, READONLY, DEBUGGING, OCTETS
```

Checking the contents of .debug_info

```bash
$ objdump -s -j .debug_info run.exe
Contents of section .debug_info:
 0000 36000000 02000000 00000401 00900408  6...............
 0010 45900408 00000000 636f6465 2e61736d  E.......code.asm
 0020 004e4153 4d20322e 31352e30 35000180  .NASM 2.15.05...
 0030 02009004 08000000 0000               ..........
```

Perhaps the binary was written in assembly and assembled with NASM.

Disassembling the .text section we get

```asm
Disassembly of section .text:

08049000 <_start>:
 8049000:       5b                      pop    %ebx
 8049001:       5b                      pop    %ebx
 8049002:       5b                      pop    %ebx
 8049003:       a1 00 a0 04 08          mov    0x804a000,%eax
 8049008:       3b 03                   cmp    (%ebx),%eax
 804900a:       74 02                   je     804900e <_start.goodjob>
 804900c:       eb 18                   jmp    8049026 <_start.wrong>

0804900e <_start.goodjob>:
 804900e:       b8 04 00 00 00          mov    $0x4,%eax
 8049013:       bb 01 00 00 00          mov    $0x1,%ebx
 8049018:       b9 08 a0 04 08          mov    $0x804a008,%ecx
 804901d:       ba 0e 00 00 00          mov    $0xe,%edx
 8049022:       cd 80                   int    $0x80
 8049024:       eb 16                   jmp    804903c <_start.end>

08049026 <_start.wrong>:
 8049026:       b8 04 00 00 00          mov    $0x4,%eax
 804902b:       bb 01 00 00 00          mov    $0x1,%ebx
 8049030:       b9 16 a0 04 08          mov    $0x804a016,%ecx
 8049035:       ba 07 00 00 00          mov    $0x7,%edx
 804903a:       cd 80                   int    $0x80

0804903c <_start.end>:
 804903c:       b8 01 00 00 00          mov    $0x1,%eax
 8049041:       31 db                   xor    %ebx,%ebx
 8049043:       cd 80                   int    $0x80
```

The binary's entry point is `_start`. The three pop instructions are used to pop argc, argv[0] and argv[1] into `ebx` so that it contains the value of argv[1]. Data at `0x804a000` is loaded into `eax`.

Examining the .data section

```asm
Contents of section .data:
 804a000 50343535 77307264 596f7520 476f7420  P455w0rdYou Got
 804a010 54686973 210a5772 6f6e6721 0a        This!.Wrong!.
```

We find that there is a string "P455w0rd" at the memory location along with other strings. When this data is loaded into `eax`, it contains only the first four characters "P455".

Looking at the disassembly, The value at memory location loaded in `ebx` is compared to `eax`. As `ebx` contains argv[1] which is a pointer to the string passed as command line argument to the program, the string is being compared with "P455". If both are equal then control jumps to `_start.goodjob`, prints "You Got This!" by calling write system call and then calls exit system call.

Therefore providing any string starting with "P455" is acceptable.
