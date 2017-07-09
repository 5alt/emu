# author: md5_salt
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from struct import unpack, pack, unpack_from, calcsize

import binascii
try:
    import hexdump
except ImportError:
    pass

PAGE_ALIGN = 0x1000  # 4k

COMPILE_GCC = 1
COMPILE_MSVC = 2

TRACE_OFF = 0
TRACE_DATA_READ = 1
TRACE_DATA_WRITE = 2
TRACE_CODE = 4


class Emu(object):
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000000, \
                 ssize=3):
        assert (arch in [UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64])
        self.arch = arch
        self.mode = mode
        self.compiler = compiler
        self.stack = self._alignAddr(stack)
        self.mmaped = []
        self.ssize = ssize
        self.curUC = None
        self.traceOption = TRACE_OFF
        self.logBuffer = []
        self.altFunc = {}
        self.hooks = []
        self.curUC = Uc(self.arch, self.mode)
        self._init()

    def _initArgs(self, RA, args):
        sp = self.curUC.reg_read(self.REG_SP)
        if self.REG_RA == 0:
            self.curUC.mem_write(sp, pack(self.pack_fmt, RA))
        else:
            self.curUC.reg_write(self.REG_RA, RA)

        ## init the arguments
        i = 0
        while i < len(self.REG_ARGS) and i < len(args):
            self.curUC.reg_write(self.REG_ARGS[i], args[i])
            i += 1

        while i < len(args):
            sp += self.step
            self.curUC.mem_write(sp, pack(self.pack_fmt, args[i]))
            i += 1

    def malloc(self, address, length):
        addr = self._alignAddr(address)
        size = self._alignAddr(length) + PAGE_ALIGN
        
        for start, length in self.mmaped:
            if addr >= start and addr + size <= start + length: # already mmaped
                return
            elif addr < start and start < addr + size <= start + length: # left overlap
                nl = start - addr
                self.curUC.mem_map(addr, nl)
                self.mmaped.remove((start, length))
                self.mmaped.append((addr, nl + length))
                return
            elif addr >= start and addr + size > start + length > addr: # ritht overlap
                nl = (addr + size) - (start + length)
                self.curUC.mem_map(start + length, nl)
                self.mmaped.remove((start, length))
                self.mmaped.append((start, nl + length))
                return
            elif addr < start and addr + size > start + length: # both overlap
                nl1 = start - addr
                self.curUC.mem_map(addr, nl)
                nl2 = (addr + size) - (start + length)
                self.curUC.mem_map(start + length, nl)
                self.mmaped.remove((start, length))
                self.mmaped.append((addr, size))
                return
        self.curUC.mem_map(addr, size)
        self.mmaped.append((addr, size))

    # set the data before emulation
    def setData(self, address, data):
        addr = self._alignAddr(address)
        self.malloc(addr, len(data))
        self.curUC.mem_write(address, data)

    def readData(self, addr, size):
        return self.curUC.mem_read(addr, size)

    def setReg(self, reg, value):
        self.curUC.reg_write(reg, value)

    def readReg(self, reg):
        return self.curUC.reg_read(reg)

    def _getBit(self, value, offset):
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def _clearHooks(self):
        for h in self.hooks:
            self.curUC.hook_del(h)

    def run(self, startAddr, stopAddr, args=[], TimeOut=0, Count=0):
        try:
            self._clearHooks()
            self._initArgs(stopAddr, args)
            self.logBuffer = []
            
            # add the invalid memory access hook
            self.hooks.append(self.curUC.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid))

            # add the trace hook
            if self.traceOption & (TRACE_DATA_READ | TRACE_DATA_WRITE):
                self.hooks.append(self.curUC.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_mem_access))

            self.hooks.append(self.curUC.hook_add(UC_HOOK_CODE, self._hook_code))

            # start emulate
            self.curUC.emu_start(startAddr, stopAddr, timeout=TimeOut, count=Count)
        except UcError as e:
            print("#ERROR: %s" % e)

    def setTrace(self, opt):
        if opt != TRACE_OFF:
            self.traceOption |= opt
        else:
            self.traceOption = TRACE_OFF

    def _addTrace(self, logInfo):
        self.logBuffer.append(logInfo)

    def showTrace(self):
        logs = "\n".join(self.logBuffer)
        print(logs)

    def alt(self, address, func, argc, balance=False):
        """
        If call the address, will call the func instead.
        the arguments of func : func(self.curUC, consoleouput, args)
        """
        assert (callable(func))
        self.altFunc[address] = (func, argc, balance)

    def dumpData(self, addr, size):
        data = str(self.readData(addr, size))
        try:
            hexdump.hexdump(data)
        except:
            for i in range(0, size, 4):
                if i % 16 == 0: print("")
                print(binascii.hexlify(data[i:i+4]), end=' ')

    # callback for tracing invalid memory access (READ or WRITE, FETCH)
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            addr = self._alignAddr(address)
            self.malloc(addr, PAGE_ALIGN)
            return True

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._addTrace("### Memory WRITE at 0x%x, data size = %u, data value = 0x%x" \
                           % (address, size, value))
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._addTrace("### Memory READ at 0x%x, data size = %u" \
                           % (address, size))

    def _hook_code(self, uc, address, size, user_data):
        if self.traceOption & TRACE_CODE:
            self._addTrace("### Trace Instruction at 0x%x, size = %u" % (address, size))
        if address in self.altFunc.keys():
            func, argc, balance = self.altFunc[address]
            try:
                sp = uc.reg_read(self.REG_SP)
                if self.REG_RA == 0:
                    RA = unpack(self.pack_fmt, str(uc.mem_read(sp, self.step)))[0]
                    sp += self.step
                else:
                    RA = uc.reg_read(self.REG_RA)

                args = []
                i = 0
                while i < argc and i < len(self.REG_ARGS):
                    args.append(uc.reg_read(self.REG_ARGS[i]))
                    i += 1
                sp2 = sp
                while i < argc:
                    args.append(unpack(self.pack_fmt, str(uc.mem_read(sp2, self.step)))[0])
                    sp2 += self.step
                    i += 1

                res = func(uc, self.logBuffer, args)
                if type(res) != int: res = 0
                uc.reg_write(self.REG_RES, res)
                uc.reg_write(self.REG_PC, RA)
                if balance:
                    uc.reg_write(self.REG_SP, sp2)
                else:
                    uc.reg_write(self.REG_SP, sp)
            except Exception as e:
                self._addTrace("alt exception: %s" % e)

    def _alignAddr(self, addr):
        #return addr
        return addr // PAGE_ALIGN * PAGE_ALIGN

    def showRegs(self, *regs):
        for reg in regs:
            print("0x%x" % self.curUC.reg_read(reg))

    def _init(self):
        if self.arch == UC_ARCH_X86:
            if self.mode == UC_MODE_16:
                self.step = 2
                self.pack_fmt = '<H'
                self.REG_PC = UC_X86_REG_IP
                self.REG_SP = UC_X86_REG_SP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_AX
                self.REG_ARGS = []
            elif self.mode == UC_MODE_32:
                self.step = 4
                self.pack_fmt = '<I'
                self.REG_PC = UC_X86_REG_EIP
                self.REG_SP = UC_X86_REG_ESP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_EAX
                self.REG_ARGS = []
            elif self.mode == UC_MODE_64:
                self.step = 8
                self.pack_fmt = '<Q'
                self.REG_PC = UC_X86_REG_RIP
                self.REG_SP = UC_X86_REG_RSP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_RAX
                if self.compiler == COMPILE_GCC:
                    self.REG_ARGS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                                     UC_X86_REG_R8, UC_X86_REG_R9]
                elif self.compiler == COMPILE_MSVC:
                    self.REG_ARGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        elif self.arch == UC_ARCH_ARM:
            if self.mode == UC_MODE_ARM:
                self.step = 4
                self.pack_fmt = '<I'
            elif self.mode == UC_MODE_THUMB:
                self.step = 2
                self.pack_fmt = '<H'
            self.REG_PC = UC_ARM_REG_PC
            self.REG_SP = UC_ARM_REG_SP
            self.REG_RA = UC_ARM_REG_LR
            self.REG_RES = UC_ARM_REG_R0
            self.REG_ARGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        elif self.arch == UC_ARCH_ARM64:
            self.step = 8
            self.pack_fmt = '<Q'
            self.REG_PC = UC_ARM64_REG_PC
            self.REG_SP = UC_ARM64_REG_SP
            self.REG_RA = UC_ARM64_REG_LR
            self.REG_RES = UC_ARM64_REG_X0
            self.REG_ARGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                             UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]

        # init stack
        self.malloc(self.stack, (self.ssize + 1) * PAGE_ALIGN * 2)
        sp = self.stack + self.ssize * PAGE_ALIGN
        self.curUC.reg_write(self.REG_SP, sp)

    def _showRegs(self):
        print(">>> regs:")
        eflags = None
        try:
            if self.arch == UC_ARCH_X86:
                if self.mode == UC_MODE_16:
                    ax = self.curUC.reg_read(UC_X86_REG_AX)
                    bx = self.curUC.reg_read(UC_X86_REG_BX)
                    cx = self.curUC.reg_read(UC_X86_REG_CX)
                    dx = self.curUC.reg_read(UC_X86_REG_DX)
                    di = self.curUC.reg_read(UC_X86_REG_SI)
                    si = self.curUC.reg_read(UC_X86_REG_DI)
                    bp = self.curUC.reg_read(UC_X86_REG_BP)
                    sp = self.curUC.reg_read(UC_X86_REG_SP)
                    ip = self.curUC.reg_read(UC_X86_REG_IP)
                    eflags = self.curUC.reg_read(UC_X86_REG_EFLAGS)

                    print("    AX = 0x%x BX = 0x%x CX = 0x%x DX = 0x%x" % (ax, bx, cx, dx))
                    print("    DI = 0x%x SI = 0x%x BP = 0x%x SP = 0x%x" % (di, si, bp, sp))
                    print("    IP = 0x%x" % ip)
                elif self.mode == UC_MODE_32:
                    eax = self.curUC.reg_read(UC_X86_REG_EAX)
                    ebx = self.curUC.reg_read(UC_X86_REG_EBX)
                    ecx = self.curUC.reg_read(UC_X86_REG_ECX)
                    edx = self.curUC.reg_read(UC_X86_REG_EDX)
                    edi = self.curUC.reg_read(UC_X86_REG_ESI)
                    esi = self.curUC.reg_read(UC_X86_REG_EDI)
                    ebp = self.curUC.reg_read(UC_X86_REG_EBP)
                    esp = self.curUC.reg_read(UC_X86_REG_ESP)
                    eip = self.curUC.reg_read(UC_X86_REG_EIP)
                    eflags = self.curUC.reg_read(UC_X86_REG_EFLAGS)

                    print("    EAX = 0x%x EBX = 0x%x ECX = 0x%x EDX = 0x%x" % (eax, ebx, ecx, edx))
                    print("    EDI = 0x%x ESI = 0x%x EBP = 0x%x ESP = 0x%x" % (edi, esi, ebp, esp))
                    print("    EIP = 0x%x" % eip)
                elif self.mode == UC_MODE_64:
                    rax = self.curUC.reg_read(UC_X86_REG_RAX)
                    rbx = self.curUC.reg_read(UC_X86_REG_RBX)
                    rcx = self.curUC.reg_read(UC_X86_REG_RCX)
                    rdx = self.curUC.reg_read(UC_X86_REG_RDX)
                    rdi = self.curUC.reg_read(UC_X86_REG_RSI)
                    rsi = self.curUC.reg_read(UC_X86_REG_RDI)
                    rbp = self.curUC.reg_read(UC_X86_REG_RBP)
                    rsp = self.curUC.reg_read(UC_X86_REG_RSP)
                    rip = self.curUC.reg_read(UC_X86_REG_RIP)
                    r8 = self.curUC.reg_read(UC_X86_REG_R8)
                    r9 = self.curUC.reg_read(UC_X86_REG_R9)
                    r10 = self.curUC.reg_read(UC_X86_REG_R10)
                    r11 = self.curUC.reg_read(UC_X86_REG_R11)
                    r12 = self.curUC.reg_read(UC_X86_REG_R12)
                    r13 = self.curUC.reg_read(UC_X86_REG_R13)
                    r14 = self.curUC.reg_read(UC_X86_REG_R14)
                    r15 = self.curUC.reg_read(UC_X86_REG_R15)
                    eflags = self.curUC.reg_read(UC_X86_REG_EFLAGS)

                    print("    RAX = 0x%x RBX = 0x%x RCX = 0x%x RDX = 0x%x" % (rax, rbx, rcx, rdx))
                    print("    RDI = 0x%x RSI = 0x%x RBP = 0x%x RSP = 0x%x" % (rdi, rsi, rbp, rsp))
                    print("    R8 = 0x%x R9 = 0x%x R10 = 0x%x R11 = 0x%x R12 = 0x%x " \
                          "R13 = 0x%x R14 = 0x%x R15 = 0x%x" % (r8, r9, r10, r11, r12, r13, r14, r15))
                    print("    RIP = 0x%x" % rip)
                if eflags:
                    print("    EFLAGS:")
                    print("    CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d " \
                          "NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d"
                          % (self._getBit(eflags, 0),
                             self._getBit(eflags, 2),
                             self._getBit(eflags, 4),
                             self._getBit(eflags, 6),
                             self._getBit(eflags, 7),
                             self._getBit(eflags, 8),
                             self._getBit(eflags, 9),
                             self._getBit(eflags, 10),
                             self._getBit(eflags, 11),
                             self._getBit(eflags, 12) + self._getBit(eflags, 13) * 2,
                             self._getBit(eflags, 14),
                             self._getBit(eflags, 16),
                             self._getBit(eflags, 17),
                             self._getBit(eflags, 18),
                             self._getBit(eflags, 19),
                             self._getBit(eflags, 20),
                             self._getBit(eflags, 21)))
        except UcError as e:
            print("#ERROR: %s" % e)
