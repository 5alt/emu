# emu
emu is a code emulator base on [unicorn engine](http://www.unicorn-engine.org/).

It is inspired by [idaemu](https://github.com/36hours/idaemu) and made some modification.

Supported architecture

* X86 (16, 32, 64-bit)
* ARM
* ARM64 (ARMv8)

## features

* automatic memory management
* code tracing && memory access tracing
* apis for human

## install
[unicorn-engine](http://www.unicorn-engine.org/download/)

hexdump (recommend)

## examples

```
from emu import *

a = Emu(UC_ARCH_X86, UC_MODE_32)
X86_CODE32 = b"\x41\x4a" # INC ecx; DEC edx
base_address = 0x1000000
a.setData(base_address, X86_CODE32)
a.setReg(UC_X86_REG_ECX, 0x1234)
a.setReg(UC_X86_REG_EDX, 0x7890)
a.run(base_address, base_address + len(X86_CODE32), TimeOut=3)
print(a.readReg(UC_X86_REG_ECX))
```

## contact

md5_salt [AT] 0ops.net