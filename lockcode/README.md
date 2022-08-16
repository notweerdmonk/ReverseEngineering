# lockcode

[crackmes.one - lockcode](https://crackmes.one/crackme/5fda4fa433c5d41f64dee37b)

The binary is fairly straighforward ELF with all symbols intact. Even there is debug data. Running it prints a message indicating that it needs some arguments, not just any arguments however.

Disassembling `main` function, we find that there is a check at `0x1239` for argc ($rdi). If argc equals two, control branches to `0x1255` else the program stops after printing a message.
```assembly
   0x000000000000121a <+4>:	push   rbp
   0x000000000000121b <+5>:	mov    rbp,rsp
   0x000000000000121e <+8>:	push   rbx
   0x000000000000121f <+9>:	sub    rsp,0x58
   0x0000000000001223 <+13>:	mov    DWORD PTR [rbp-0x54],edi
   0x0000000000001226 <+16>:	mov    QWORD PTR [rbp-0x60],rsi
   0x000000000000122a <+20>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000001233 <+29>:	mov    QWORD PTR [rbp-0x18],rax
   0x0000000000001237 <+33>:	xor    eax,eax
   0x0000000000001239 <+35>:	cmp    DWORD PTR [rbp-0x54],0x2
   0x000000000000123d <+39>:	je     0x1255 <main+63>
   0x000000000000123f <+41>:	lea    rdi,[rip+0xe05]        # 0x204b
   0x0000000000001246 <+48>:	call   0x1070 <puts@plt>
   0x000000000000124b <+53>:	mov    eax,0x0
   0x0000000000001250 <+58>:	jmp    0x12ef <main+217>
```

The following code puts a string `wzJCPjBHBsHAkHbazmhYdflzLdhapPUE` on to the stack.
```assembly
   0x0000000000001255 <+63>:	movabs rax,0x48426a50434a7a77
   0x000000000000125f <+73>:	movabs rdx,0x6162486b41487342
   0x0000000000001269 <+83>:	mov    QWORD PTR [rbp-0x40],rax
   0x000000000000126d <+87>:	mov    QWORD PTR [rbp-0x38],rdx
   0x0000000000001271 <+91>:	movabs rax,0x7a6c666459686d7a
   0x000000000000127b <+101>:	movabs rdx,0x455550706168644c
   0x0000000000001285 <+111>:	mov    QWORD PTR [rbp-0x30],rax
   0x0000000000001289 <+115>:	mov    QWORD PTR [rbp-0x28],rdx
   0x000000000000128d <+119>:	mov    BYTE PTR [rbp-0x20],0x0
```

Rest of the code finds the length of this string. The function `val` takes the string and its length as arguments, adds all the bytes in the string and returns the sum.
```assembly
   0x0000000000001291 <+123>:	lea    rax,[rbp-0x40]
   0x0000000000001295 <+127>:	mov    rdi,rax
   0x0000000000001298 <+130>:	call   0x1080 <strlen@plt>
   0x000000000000129d <+135>:	mov    edx,eax
   0x000000000000129f <+137>:	lea    rax,[rbp-0x40]
   0x00000000000012a3 <+141>:	mov    rsi,rax
   0x00000000000012a6 <+144>:	mov    edi,edx
   0x00000000000012a8 <+146>:	call   0x1189 <val>
```

Next the same procedure is repeated for the command line argument. Then both sums are passed to another function `res` which just checks if these two are equal or not. Actually, 1 is added to the sum generated internally and then the sum of user's argument is subtracted. The result is compared to 1 again.

```assembly
   0x00000000000011db <+12>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000000011de <+15>:	mov    DWORD PTR [rbp-0x8],esi
   0x00000000000011e1 <+18>:	add    DWORD PTR [rbp-0x4],0x1
   0x00000000000011e5 <+22>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000000011e8 <+25>:	sub    eax,DWORD PTR [rbp-0x8]
   0x00000000000011eb <+28>:	cmp    eax,0x1
```
