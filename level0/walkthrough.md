# Level0

Once logged in, we have access to a binary : `level0` 

Running it without arguments results in a segfault

Running it with any argument results in getting a `No!` printed..

Based on that we guess that we should provide it the right argument, but which one ?

We do not have any sudo rights, using it on /home/user/level1/.pass (where the password is located) does not work, and de-compiling it doesn’t give a useful result

So the last thing to try is to read the assembly ! yay

```bash
level0@RainFall:~$ gdb level0

[...]

(gdb) break main
Breakpoint 1 at 0x8048ec3
(gdb) run
Starting program: /home/user/level0/level0

Breakpoint 1, 0x08048ec3 in main ()
(gdb) disas main
Dump of assembler code for function main:
```

```nasm
   [...]
   0x08048ec9 <+9>:     mov    eax,DWORD PTR [ebp+0xc]      // Put argv into eax
   0x08048ecc <+12>:    add    eax,0x4                      // Go 4 bytes up so argv[1]
   0x08048ecf <+15>:    mov    eax,DWORD PTR [eax]          // Make sure we have a 32 bytes ptr
   0x08048ed1 <+17>:    mov    DWORD PTR [esp],eax          // Push it on the stack
   0x08048ed4 <+20>:    call   0x8049710 <atoi>             // Run atoi on it
   0x08048ed9 <+25>:    cmp    eax,0x1a7                    // Compare the result with 0x1a7 (423)
```

This was probably the most important part but for completeness here is the rest of the code explained :

```nasm
   0x08048ede <+30>:    jne    0x8048f58 <main+152>         // If it is not equal jump to a later point
   0x08048ee0 <+32>:    mov    DWORD PTR [esp],0x80c5348    // Push a certain string to the stack
   0x08048ee7 <+39>:    call   0x8050bf0 <strdup>           // Duplicate it
   0x08048eec <+44>:    mov    DWORD PTR [esp+0x10],eax     // Push the duplicated string on the stack...
   0x08048ef0 <+48>:    mov    DWORD PTR [esp+0x14],0x0     // ... followed by a \0
   0x08048ef8 <+56>:    call   0x8054680 <getegid>          // Run getegid (returns the effective group ID of the calling process)
   0x08048efd <+61>:    mov    DWORD PTR [esp+0x1c],eax     // Push the result on the stack
   0x08048f01 <+65>:    call   0x8054670 <geteuid>          // Run geteuid (returns the effective user ID of the calling process)
   0x08048f06 <+70>:    mov    DWORD PTR [esp+0x18],eax     // Push the result on the stack
   0x08048f0a <+74>:    mov    eax,DWORD PTR [esp+0x1c]     // Get the result of getegid in eax
   0x08048f0e <+78>:    mov    DWORD PTR [esp+0x8],eax      // Push it again on the stack as the 3rd argument of something
   0x08048f12 <+82>:    mov    eax,DWORD PTR [esp+0x1c]     // Then again
   0x08048f16 <+86>:    mov    DWORD PTR [esp+0x4],eax      // Same thing but 2nd argument
   0x08048f1a <+90>:    mov    eax,DWORD PTR [esp+0x1c]     // Same thing
   0x08048f1e <+94>:    mov    DWORD PTR [esp],eax          // Same thing but first argument
   0x08048f21 <+97>:    call   0x8054700 <setresgid>        // Run setresgid (sets real, effective, group id with the arguments on the stack)
   0x08048f26 <+102>:   mov    eax,DWORD PTR [esp+0x18]     // Now get the result of geteuid
   0x08048f2a <+106>:   mov    DWORD PTR [esp+0x8],eax      // And put it on the stack as the 3rd argument
   0x08048f2e <+110>:   mov    eax,DWORD PTR [esp+0x18]     // Same thing
   0x08048f32 <+114>:   mov    DWORD PTR [esp+0x4],eax      // Same thing but 2nd argument
   0x08048f36 <+118>:   mov    eax,DWORD PTR [esp+0x18]     // Same thing
   0x08048f3a <+122>:   mov    DWORD PTR [esp],eax          // Same thing but first argument
   0x08048f3d <+125>:   call   0x8054690 <setresuid>        // Call setresuid (same thing as setresgid but for user id)
   0x08048f42 <+130>:   lea    eax,[esp+0x10]               // Makes eax points to the string that was duplicated earlier
   0x08048f46 <+134>:   mov    DWORD PTR [esp+0x4],eax      // Set that as second argument
   0x08048f4a <+138>:   mov    DWORD PTR [esp],0x80c5348    // And some string as first argument
   0x08048f51 <+145>:   call   0x8054640 <execv>            // Then execute it
   0x08048f56 <+150>:   jmp    0x8048f80 <main+192>         // And jump to the end
   0x08048f58 <+152>:   mov    eax,ds:0x80ee170             // [ This part is the 'error' part, probably what prints 'No!'
   0x08048f5d <+157>:   mov    edx,eax                      // | when we provide the wrong argument
   0x08048f5f <+159>:   mov    eax,0x80c5350                // |
   0x08048f64 <+164>:   mov    DWORD PTR [esp+0xc],edx      // |
   0x08048f68 <+168>:   mov    DWORD PTR [esp+0x8],0x5      // |
   0x08048f70 <+176>:   mov    DWORD PTR [esp+0x4],0x1      // |
   0x08048f78 <+184>:   mov    DWORD PTR [esp],eax          // |
   0x08048f7b <+187>:   call   0x804a230 <fwrite>           // ]
   0x08048f80 <+192>:   mov    eax,0x0                      // Set return's value to 0
   0x08048f85 <+197>:   leave
   0x08048f86 <+198>:   ret
```

So, as we can see, when we input 423 as argument, it should execute something, let’s try it

```nasm
level0@RainFall:~$ ./level0 423
$ pwd
/home/user/level0
$ id
uid=2030(level1) gid=2020(level0) groups=2030(level1),100(users),2020(level0)
```

And it seems we are given a shell as the level1 user ! Let’s get the password

```nasm
$ cd /home/user/level1/
$ cat .pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
