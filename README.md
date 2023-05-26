# AIS-2023-pre-exam

## 前言
很高興今年參與 AIS Pre-exam 及 MyfirstCTF的出題，因為兩場比賽同時進行，這次出題設計是初學者導向，希望大家在解題中可以找到成就感，並從中找到解 CTF 的樂趣。

## [Crypto] Fernet 
AIS3-Pre-exam 177 Solves, My First CTF - 58 Solves

此題為 Crypto 簽到題，在思考要如何出的不會太難，又可讓同學體驗到解題的樂趣，於是決定出了一題簡單的對稱式加密
。你只要上網搜尋一下 Fernet 就會知道這是一種對稱式加密的演算法，這題原本打算要用其他方式去 leak 出 public key，再用 public key 去解密，但考量到是 easy 的題目，所以直接將 public key 放在程式裡面，你只需要知道他是對稱式加密，並且花點時間研究一下文檔或是網路上的相關資訊，就會知道如何使用 library 解出這題。
```python
import os
import base64
from cryptography.fernet import Fernet
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from secret import FLAG

def encrypt(plaintext, password):
    salt = os.urandom(16)  
    key = PBKDF2(password.encode(), salt, 32, count=1000, hmac_hash_module=SHA256)  
    f = Fernet(base64.urlsafe_b64encode(key))  
    ciphertext = f.encrypt(plaintext.encode())  
    return base64.b64encode(salt + ciphertext).decode()

# Usage:
leak_password = 'mysecretpassword'
plaintext = FLAG

# Encrypt
ciphertext = encrypt(plaintext, leak_password)
print("Encrypted data:",ciphertext)
```
[exploit.py](https://github.com/Richard-YH/AIS3-2023-pre-exam/blob/main/Fernet/sol/exploit.py) 




## [PWN] ManagementSystem 
AIS3-Pre-exam 39 Solves, My First CTF - 3 Solves

這題打開程式可能很多人會以為這一百多行的程式是要解 heap over flow，但這題是 easy 的題目，只要再把程式看完，會發現其實這支程式的漏洞只是簡單的 buffer over flow，delete_user function 會使用 gets 函數來讀取 buffer，如果你一開始有先看 makefile，並且有嘗試 make 檔案，其實編譯器也會告訴你 'gets' function is dangerous and should not be used，
```shell
ms.c:(.text+0x2c9): warning: the `gets' function is dangerous and should not be used.
```
找到程式的漏洞位置之後，可以用 objdump 來看程式反組繹的結果，會看到 buffer 儲存 old rbp 的距離為 0x60， 再加上 rbp 的 0x8 個 byte，共 0x68 個 byte ，將它填滿之後就是我們的 return address，而程式中還有一些隱藏小 bug ，即便你找到了正確的距離，可能會導致你的 exploit 沒辦法正常直行到 secret function，這邊請練習各種除錯技巧。
```shell
  40156d:	e8 ae fb ff ff       	callq  401120 <printf@plt>
  401572:	48 8d 45 a0          	lea    -0x60(%rbp),%rax
  401576:	48 89 c7             	mov    %rax,%rdi
  401579:	b8 00 00 00 00       	mov    $0x0,%eax
  40157e:	e8 cd fb ff ff       	callq  401150 <gets@plt>
  401583:	48 8d 55 9c          	lea    -0x64(%rbp),%rdx
  401587:	48 8d 45 a0          	lea    -0x60(%rbp),%rax
  40158b:	48 8d 35 df 0b 00 00 	lea    0xbdf(%rip),%rsi        # 402171 <_IO_stdin_used+0x171>
  401592:	48 89 c7             	mov    %rax,%rdi
  401595:	b8 00 00 00 00       	mov    $0x0,%eax
  40159a:	e8 d1 fb ff ff       	callq  401170 <__isoc99_sscanf@plt>
  ```
而不知道如何執行到的 secret_function 也可以透過反組譯的方式找到位置在 0x40131b，因為編譯選項 -no-pie 緣故，記憶體分配的位置會是固定的。最後你的 exploit 只要執行 delete_user 的選項，並送入 buffer 的距離及return address 的位置，就可以成功進入到 secret_functions，便可成功 RCE。
```shell
000000000040131b <secret_function>:
  40131b:	f3 0f 1e fa          	endbr64 
  40131f:	55                   	push   %rbp
  401320:	48 89 e5             	mov    %rsp,%rbp
  401323:	48 83 ec 10          	sub    $0x10,%rsp
  401327:	48 8d 3d da 0c 00 00 	lea    0xcda(%rip),%rdi        # 402008 <_IO_stdin_used+0x8>
  40132e:	e8 dd fd ff ff       	callq  401110 <puts@plt>
  401333:	48 8d 05 11 0d 00 00 	lea    0xd11(%rip),%rax        # 40204b <_IO_stdin_used+0x4b>
  40133a:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  40133e:	48 c7 45 f8 00 00 00 	movq   $0x0,-0x8(%rbp)
  ```
[exploit.py](https://github.com/Richard-YH/AIS3-2023-pre-exam/blob/main/ManagementSystem/sol/exploit.py) 
