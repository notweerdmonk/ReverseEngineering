
# Bomb Lab CS:APP2e CMU

Before we plunge into lines of assembly code here is some background. This reverse engineering task is part of a course offered at CMU (http://csapp.cs.cmu.edu/public/labs.html). Its appropriately named Bomb Lab (:P) as the task provides a 'binary bomb' to students. This binary requires six strings from the user which are read either from the standard input or a text file. Providing an incorrect string will set off the bomb! The students need to find the six strings to successfully defuse the bomb.

I stumbled upon this on the internet few years back when I was beginning to learn reversing binaries. Many thanks to _xuzhezhaozhao_ (https://github.com/xuzhezhaozhao/CSAPP-Labs/tree/master/bomb%20lab) for sharing the binary and lab writeup with the less fortunate ones. You will be provided with a tar file containing the binary.

Now armed with linux, bash and the ever amazing gdb, we set out to defuse this binary bomb.

```shell
$ file bomb
bomb: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.0.0, not stripped
```
The binary is a 32-bit ELF. You need to setup a 32 bit environment. Easiest way is to use a virtual machine emulator/hypervisor like qemu, VirtualBox, vagrant or whatever other virtual machine makes feel sane. Next you need a 32-bit Linux distro (you can also do this on a Windows or Mac machine, look around the internet). Make sure to have atleast the common Unix tools like file, strings, gdb, etc installed before you proceed. This task helped me learn about gdb in an entirely new light.

Load the binary with gdb and set a breakpoint at `phase_1`.

```assembly
$ gdb -q bomb
(gdb) b phase_1
```
## phase 1

Now let us disassemble `phase_1`.

```assembly
(gdb) disas phase_1
Dump of assembler code for function phase_1:
   0x08048b20 <+0>:	  push   ebp
   0x08048b21 <+1>:	  mov    ebp,esp
   0x08048b23 <+3>:	  sub    esp,0x8
   ; load arg into eax
   0x08048b26 <+6>:	  mov    eax,DWORD PTR [ebp+0x8]
   0x08048b29 <+9>:   add    esp,0xfffffff8
   ; push string to compare our input against
   0x08048b2c <+12>:  push   0x80497c0
   ; push input string
   0x08048b31 <+17>:  push   eax
   ; compare two strings
   0x08048b32 <+18>:  call   0x8049030 <strings_not_equal>
   0x08048b37 <+23>:  add    esp,0x10
   0x08048b3a <+26>:  test   eax,eax
   0x08048b3c <+28>:  je     0x8048b43 <phase_1+35>
   0x08048b3e <+30>:  call   0x80494fc <explode_bomb>
   0x08048b43 <+35>:  mov    esp,ebp
   0x08048b45 <+37>:  pop    ebp
   0x08048b46 <+38>:  ret    
```
It is not entirely necessary to analyze `strings_not_equal` at this point. If you have some prior experience with assembly code, it is easy to understand that there are atleast two arguments to this function which are being pushed to the stack. The first one is the input string and the second is a readonly string in the data section. The string comparision function will return 0 if two strings match exactly else it will return 0.

```assembly
Dump of assembler code for function strings_not_equal:
...
   0x08049055 <+37>:	je     0x8049060 <strings_not_equal+48>
   ; return 1 if strings do not match exactly
   0x08049057 <+39>:	mov    eax,0x1
   0x0804905c <+44>:	jmp    0x804907f <strings_not_equal+79>
   0x0804905e <+46>:	mov    esi,esi
   0x08049060 <+48>:	mov    edx,esi
   0x08049062 <+50>:	mov    ecx,edi
   0x08049064 <+52>:	cmp    BYTE PTR [edx],0x0
   0x08049067 <+55>:	je     0x804907d <strings_not_equal+77>
   0x08049069 <+57>:	lea    esi,[esi+eiz*1+0x0]
   0x08049070 <+64>:	mov    al,BYTE PTR [edx]
   0x08049072 <+66>:	cmp    al,BYTE PTR [ecx]
   0x08049074 <+68>:	jne    0x8049057 <strings_not_equal+39>
   0x08049076 <+70>:	inc    edx
   0x08049077 <+71>:	inc    ecx
   ; keep checking till end of input string
   0x08049078 <+72>:	cmp    BYTE PTR [edx],0x0
   0x0804907b <+75>:	jne    0x8049070 <strings_not_equal+64>
   0x0804907d <+77>:	xor    eax,eax
   0x0804907f <+79>:	lea    esp,[ebp-0x18]
   0x08049082 <+82>:	pop    ebx
   0x08049083 <+83>:	pop    esi
   0x08049084 <+84>:	pop    edi
   0x08049085 <+85>:	mov    esp,ebp
   0x08049087 <+87>:	pop    ebp
   0x08049088 <+88>:	ret
```
Looking at the address of the second argument we get the string against which our input will be compared. This is in fact the input for `phase_1`.

```assembly
(gdb) x/s 0x80497c0
0x80497c0:	 "Public speaking is very easy."
```
## phase 2

Let us proceed on to `phase_2`.

Analyzing `phase_2` we find that a function `read_six_numbers` is called with our input string and the address of an array to hold six `int` variables. This function simply reads six integers from the input string and stores then in an array, nothing fancy! The input string for `phase_2` should contain six space separated numbers.
```assembly
(gdb) disas phase_2
Dump of assembler code for function phase_2:
   0x08048b48 <+0>:	  push   ebp
   0x08048b49 <+1>:	  mov    ebp,esp
   0x08048b4b <+3>:	  sub    esp,0x20
   0x08048b4e <+6>:	  push   esi
   0x08048b4f <+7>:	  push   ebx
   0x08048b50 <+8>:	  mov    edx,DWORD PTR [ebp+0x8]
   0x08048b53 <+11>:  add    esp,0xfffffff8
   ; load address of array of 6 int into eax
   0x08048b56 <+14>:  lea    eax,[ebp-0x18]
   0x08048b59 <+17>:  push   eax
   0x08048b5a <+18>:  push   edx
   ; read_size_numbers populates this array from input string
   0x08048b5b <+19>:  call   0x8048fd8 <read_six_numbers>
   0x08048b60 <+24>:  add    esp,0x10
   ; first integer should be 1 else bomb explodes
   0x08048b63 <+27>:  cmp    DWORD PTR [ebp-0x18],0x1
   0x08048b67 <+31>:  je     0x8048b6e <phase_2+38>
   0x08048b69 <+33>:  call   0x80494fc <explode_bomb>
   ; ebx is set to 1 and later used to index into the arry
   0x08048b6e <+38>:  mov    ebx,0x1
   ; load address of the array into esi
   0x08048b73 <+43>:  lea    esi,[ebp-0x18]
   ; eax is set as ebx + 1
   0x08048b76 <+46>:  lea    eax,[ebx+0x1]
   ; eax = (index + 1) * array[index - 1]
   0x08048b79 <+49>:  imul   eax,DWORD PTR [esi+ebx*4-0x4]
   0x08048b7e <+54>:  cmp    DWORD PTR [esi+ebx*4],eax
   ; check array[index] == eax
   0x08048b81 <+57>:  je     0x8048b88 <phase_2+64>
   0x08048b83 <+59>:  call   0x80494fc <explode_bomb>
   ; increment index
   0x08048b88 <+64>:  inc    ebx
   ; loop over the array 
   0x08048b89 <+65>:  cmp    ebx,0x5
   0x08048b8c <+68>:  jle    0x8048b76 <phase_2+46>
   0x08048b8e <+70>:  lea    esp,[ebp-0x28]
   0x08048b91 <+73>:  pop    ebx
   0x08048b92 <+74>:  pop    esi
   0x08048b93 <+75>:  mov    esp,ebp
   0x08048b95 <+77>:  pop    ebp
   0x08048b96 <+78>:  ret
```
Looking at the next instructions we find that the first number should be 1 and rest terms of the sequence should obey the rule:

```
array[n] = n * array[n-1]
```
Starting with 1, six numbers in the sequence are 1, 2, 6, 24, 120, 720.

## phase 3

```assembly
(gdb) disas phase_3
Dump of assembler code for function phase_3:
   ; load arg into edx
   0x08048b9f <+7>:	  mov    edx,DWORD PTR [ebp+0x8]
   0x08048ba2 <+10>:	add    esp,0xfffffff4
   ; int b
   0x08048ba5 <+13>:	lea    eax,[ebp-0x4]
   0x08048ba8 <+16>:	push   eax
   ; char c
   0x08048ba9 <+17>:	lea    eax,[ebp-0x5]
   0x08048bac <+20>:	push   eax
   ; int a
   0x08048bad <+21>:	lea    eax,[ebp-0xc]
   0x08048bb0 <+24>:	push   eax
   0x08048bb1 <+25>:	push   0x80497de
   0x08048bb6 <+30>:	push   edx
   ; sscanf(input_str, "%d %c %d", &a, &c, &b)
   0x08048bb7 <+31>:	call   0x8048860 <sscanf@plt>
   0x08048bbc <+36>:	add    esp,0x20
   0x08048bbf <+39>:	cmp    eax,0x2
   0x08048bc2 <+42>:	jg     0x8048bc9 <phase_3+49>
   0x08048bc4 <+44>:	call   0x80494fc <explode_bomb>
   ; a < 7
   0x08048bc9 <+49>:	cmp    DWORD PTR [ebp-0xc],0x7
   0x08048bcd <+53>:	ja     0x8048c88 <phase_3+240>
   ; eax = a
   0x08048bd3 <+59>:	mov    eax,DWORD PTR [ebp-0xc]
   ; switch(a)
   0x08048bd6 <+62>:	jmp    DWORD PTR [eax*6+0x80497e8]
   0x08048bdd <+69>:	lea    esi,[esi+0x0]
   ; case 0: bl = 'q'
   0x08048be0 <+72>:	mov    bl,0x71
   ; if (b == 777)
   0x08048be2 <+74>:	cmp    DWORD PTR [ebp-0x4],0x309
   0x08048be9 <+81>:	je     0x8048c8f <phase_3+247>
   0x08048bef <+87>:	call   0x80494fc <explode_bomb>
   0x08048bf4 <+92>:	jmp    0x8048c8f <phase_3+247>
   0x08048bf9 <+97>:	lea    esi,[esi+eiz*1+0x0]
   ; case 1: bl = 'b'
   0x08048c00 <+104>:	mov    bl,0x62
   ; if (b == 214)
   0x08048c02 <+106>:	cmp    DWORD PTR [ebp-0x4],0xd6
   0x08048c09 <+113>:	je     0x8048c8f <phase_3+247>
   0x08048c0f <+119>:	call   0x80494fc <explode_bomb>
   0x08048c14 <+124>:	jmp    0x8048c8f <phase_3+247>
   ; case 2: bl = 'b'
   0x08048c16 <+126>:	mov    bl,0x62
   ; if (b == 755)
   0x08048c18 <+128>:	cmp    DWORD PTR [ebp-0x4],0x2f3
   0x08048c1f <+135>:	je     0x8048c8f <phase_3+247>
   0x08048c21 <+137>:	call   0x80494fc <explode_bomb>
   0x08048c26 <+142>:	jmp    0x8048c8f <phase_3+247>
   ; case 3: bl = 'k'
   0x08048c28 <+144>:	mov    bl,0x6b
   ; if (b == 251)
   0x08048c2a <+146>:	cmp    DWORD PTR [ebp-0x4],0xfb
   0x08048c31 <+153>:	je     0x8048c8f <phase_3+247>
   0x08048c33 <+155>:	call   0x80494fc <explode_bomb>
   0x08048c38 <+160>:	jmp    0x8048c8f <phase_3+247>
   0x08048c3a <+162>:	lea    esi,[esi+0x0]
   ; case 4: bl = 'o'
   0x08048c40 <+168>:	mov    bl,0x6f
   ; if (b == 160)
   0x08048c42 <+170>:	cmp    DWORD PTR [ebp-0x4],0xa0
   0x08048c49 <+177>:	je     0x8048c8f <phase_3+247>
   0x08048c4b <+179>:	call   0x80494fc <explode_bomb>
   0x08048c50 <+184>:	jmp    0x8048c8f <phase_3+247>
   ; case 5: bl = 't'
   0x08048c52 <+186>:	mov    bl,0x74
   ; if (b == 458)
   0x08048c54 <+188>:	cmp    DWORD PTR [ebp-0x4],0x1ca
   0x08048c5b <+195>:	je     0x8048c8f <phase_3+247>
   0x08048c5d <+197>:	call   0x80494fc <explode_bomb>
   0x08048c62 <+202>:	jmp    0x8048c8f <phase_3+247>
   ; case 6: bl = 'v'
   0x08048c64 <+204>:	mov    bl,0x76
   ; if (b == 780)
   0x08048c66 <+206>:	cmp    DWORD PTR [ebp-0x4],0x30c
   0x08048c6d <+213>:	je     0x8048c8f <phase_3+247>
   0x08048c6f <+215>:	call   0x80494fc <explode_bomb>
   0x08048c74 <+220>:	jmp    0x8048c8f <phase_3+247>
   ; case 7: bl = '{'
   0x08048c76 <+222>:	mov    bl,0x62
   ; if (b == 524)
   0x08048c78 <+224>:	cmp    DWORD PTR [ebp-0x4],0x20c
   0x08048c7f <+231>:	je     0x8048c8f <phase_3+247>
   0x08048c81 <+233>:	call   0x80494fc <explode_bomb>
   0x08048c86 <+238>:	jmp    0x8048c8f <phase_3+247>
   ; default
   0x08048c88 <+240>:	mov    bl,0x78
   0x08048c8a <+242>:	call   0x80494fc <explode_bomb>
   0x08048c8f <+247>:	cmp    bl,BYTE PTR [ebp-0x5]
   ; bl == c
   0x08048c92 <+250>:	je     0x8048c99 <phase_3+257>
   0x08048c94 <+252>:	call   0x80494fc <explode_bomb>
   0x08048c99 <+257>:	mov    ebx,DWORD PTR [ebp-0x18]
   0x08048c9c <+260>:	mov    esp,ebp
   0x08048c9e <+262>:	pop    ebp
   0x08048c9f <+263>:	ret
```

```assembly
(gdb) x/s 0x80497de
0x80497de:	 "%d %c %d"
```

```assembly
(gdb) x/8xw 0x80497e8
0x80497e8:	0x08048be0	0x08048c00	0x08048c16	0x08048c28
0x80497f8:	0x08048c40	0x08048c52	0x08048c64	0x08048c76
```
## phase 4

In `phase_4` an integer is read from the input string passed to `func4`.

```assembly
(gdb) disas phase_4
Dump of assembler code for function phase_4:
   0x08048ce0 <+0>:	  push   ebp
   0x08048ce1 <+1>:	  mov    ebp,esp
   0x08048ce3 <+3>:	  sub    esp,0x18
   ; load arg int edx
   0x08048ce6 <+6>:	  mov    edx,DWORD PTR [ebp+0x8]
   0x08048ce9 <+9>:	  add    esp,0xfffffffc
   ; int a
   0x08048cec <+12>:  lea    eax,[ebp-0x4]
   0x08048cef <+15>:  push   eax
   0x08048cf0 <+16>:  push   0x8049808
   0x08048cf5 <+21>:  push   edx
   ; sscanf(edx, "%d", &a)
   0x08048cf6 <+22>:  call   0x8048860 <sscanf@plt>
   0x08048cfb <+27>:  add    esp,0x10
   0x08048cfe <+30>:  cmp    eax,0x1
   0x08048d01 <+33>:  jne    0x8048d09 <phase_4+41>
   ; a != 0
   0x08048d03 <+35>:  cmp    DWORD PTR [ebp-0x4],0x0
   0x08048d07 <+39>:  jg     0x8048d0e <phase_4+46>
   0x08048d09 <+41>:  call   0x80494fc <explode_bomb>
   0x08048d0e <+46>:  add    esp,0xfffffff4
   0x08048d11 <+49>:  mov    eax,DWORD PTR [ebp-0x4]
   0x08048d14 <+52>:  push   eax
   ; func4(a)
   0x08048d15 <+53>:  call   0x8048ca0 <func4>
   0x08048d1a <+58>:  add    esp,0x10
   ; func4(a) == 55
   0x08048d1d <+61>:  cmp    eax,0x37
   0x08048d20 <+64>:  je     0x8048d27 <phase_4+71>
   0x08048d22 <+66>:  call   0x80494fc <explode_bomb>
   0x08048d27 <+71>:  mov    esp,ebp
   0x08048d29 <+73>:  pop    ebp
   0x08048d2a <+74>:  ret
```

`func4` calculates the Fibonacci sum of first `n` elements considering 0 as the 0th element where `n` is its argument.

```assembler
(gdb) disas func4
Dump of assembler code for function func4:
   0x08048ca0 <+0>:	  push   ebp
   0x08048ca1 <+1>:	  mov    ebp,esp
   0x08048ca3 <+3>:	  sub    esp,0x10
   0x08048ca6 <+6>:	  push   esi
   0x08048ca7 <+7>:	  push   ebx
   ; load arg into ebx, lets call it variable a
   0x08048ca8 <+8>:	  mov    ebx,DWORD PTR [ebp+0x8]
   ; if (a <= 1) return 1
   0x08048cab <+11>:  cmp    ebx,0x1
   0x08048cae <+14>:  jle    0x8048cd0 <func4+48>
   0x08048cb0 <+16>:  add    esp,0xfffffff4
   0x08048cb3 <+19>:  lea    eax,[ebx-0x1]
   0x08048cb6 <+22>:  push   eax
   ; esi = func4(a - 1)
   0x08048cb7 <+23>:  call   0x8048ca0 <func4>
   0x08048cbc <+28>:  mov    esi,eax
   0x08048cbe <+30>:  add    esp,0xfffffff4
   0x08048cc1 <+33>:  lea    eax,[ebx-0x2]
   0x08048cc4 <+36>:  push   eax
   ; esi += func4(a - 2)
   0x08048cc5 <+37>:  call   0x8048ca0 <func4>
   0x08048cca <+42>:  add    eax,esi
   ; return esi
   0x08048ccc <+44>:  jmp    0x8048cd5 <func4+53>
   0x08048cce <+46>:  mov    esi,esi
   0x08048cd0 <+48>:  mov    eax,0x1
   0x08048cd5 <+53>:  lea    esp,[ebp-0x18]
   0x08048cd8 <+56>:  pop    ebx
   0x08048cd9 <+57>:  pop    esi
   0x08048cda <+58>:  mov    esp,ebp
   0x08048cdc <+60>:  pop    ebp
   0x08048cdd <+61>:  ret
```

The returned sum is compared with 55. Fibonacci sum of first nine numbers in the sequence is 55.
```
0 + 1 + 1 + 2 + 3 + 5 + 8 + 13 + 21 + 34 = 55
0th 1st 2nd 3rd 4th 5th 6th 7th  8th  9th
```
## phase 5

`phase_5` requires a string of six characters as input. The lower nibble of each the ascii characters in our input string is used to index into a readonly string and populate another array of six characters. This local array is then compared to the string "giants".

```assembly
(gdb) disas phase_5
Dump of assembler code for function phase_5:
   0x08048d2c <+0>:	  push   ebp
   0x08048d2d <+1>:	  mov    ebp,esp
   0x08048d2f <+3>:	  sub    esp,0x10
   0x08048d32 <+6>:	  push   esi
   0x08048d33 <+7>:	  push   ebx
   ; load arg into ebx
   0x08048d34 <+8>:	  mov    ebx,DWORD PTR [ebp+0x8]
   0x08048d37 <+11>:  add    esp,0xfffffff4
   ; find the length of input string
   0x08048d3a <+14>:  push   ebx
   0x08048d3b <+15>:  call   0x8049018 <string_length>
   0x08048d40 <+20>:  add    esp,0x10
   ; input string should be of six characters
   0x08048d43 <+23>:  cmp    eax,0x6
   0x08048d46 <+26>:  je     0x8048d4d <phase_5+33>
   0x08048d48 <+28>:  call   0x80494fc <explode_bomb>
   ; clear edx and use it as index variable
   0x08048d4d <+33>:  xor    edx,edx
   ; load address of a local array which can hold atleast six characters, into ecx
   0x08048d4f <+35>:  lea    ecx,[ebp-0x8]
   ; load address of character array into esi
   0x08048d52 <+38>:  mov    esi,0x804b220
   ; load each ascii character from input string into al
   0x08048d57 <+43>:  mov    al,BYTE PTR [edx+ebx*1]
   ; retain the lower nibble
   0x08048d5a <+46>:  and    al,0xf
   0x08048d5c <+48>:  movsx  eax,al
   ; use the number in eax to index into the character array which esi points to
   ; load the ascii character into al
   0x08048d5f <+51>:  mov    al,BYTE PTR [eax+esi*1]
   ; save this character at into the local array also indexed with edx
   0x08048d62 <+54>:  mov    BYTE PTR [edx+ecx*1],al
   ; loop for six characters in the input string
   0x08048d65 <+57>:  inc    edx
   0x08048d66 <+58>:  cmp    edx,0x5
   0x08048d69 <+61>:  jle    0x8048d57 <phase_5+43>
   ; add null byte 
   0x08048d6b <+63>:  mov    BYTE PTR [ebp-0x2],0x0
   0x08048d6f <+67>:  add    esp,0xfffffff8
   ; compare the local array of characters with string "giants"
   0x08048d72 <+70>:  push   0x804980b
   0x08048d77 <+75>:  lea    eax,[ebp-0x8]
   0x08048d7a <+78>:  push   eax
   0x08048d7b <+79>:  call   0x8049030 <strings_not_equal>
   0x08048d80 <+84>:  add    esp,0x10
   0x08048d83 <+87>:  test   eax,eax
   0x08048d85 <+89>:  je     0x8048d8c <phase_5+96>
   0x08048d87 <+91>:  call   0x80494fc <explode_bomb>
   0x08048d8c <+96>:  lea    esp,[ebp-0x18]
   0x08048d8f <+99>:  pop    ebx
   0x08048d90 <+100>: pop    esi
   0x08048d91 <+101>: mov    esp,ebp
   0x08048d93 <+103>: pop    ebp
   0x08048d94 <+104>: ret
```
The readonly string at location `0x804b220` is:

```assembly
0x804b220 <array.123>:	 "isrveawhobpnutfg\260\001"
(gdb) x/s 0x804980b
```
The offsets in this string, for each of the letters in "giants" are:

```
offset of 'g' = 15 = 0xf
offset of 'i' = 0  = 0x0
offset of 'a' = 5  = 0x5
offset of 'n' = 11 = 0xb
offset of 't' = 13 = 0xd
offset of 's' = 1  = 0x1
```

Looking up the table of ascii codes, we need to chose six characters such that their lower nibbles correspond with the offsets we just found out above. One such string can be:

```
opekma
0x6f,0x70,0x65,0x6b,0x6d,0x61
```
## phase 6

too lazy to do a writeup without using radare2/ghidra
hint is 4 2 6 3 1 5

## secret phase

yes it exists, right alongside phase 4
hint: behave!

