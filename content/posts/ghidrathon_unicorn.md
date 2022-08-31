---
title: "Ghidrathon + Unicorn Engine + Capstone"
date: 2022-08-28T19:32:42+02:00
draft: false
---

# Ghidra with Ghidrathon + Unicorn Engine

The below script is a convenient way to combine the Ghidrathon extension (Python3 in Ghidra) developed by Mandiant [1] and the Unicorn Emulator [2]. As shown in Mandiant's blog post, unicorn is called from the Ghidrathon command line. I took that idea and automated to process a little bit.

# My Script

I created a simple Ghidra Python3 script that uses unicorn together with the capstone disassembler [3]. What you can do now is mark an area of code to emulate, run my script, choose which registers you want to set if necessary and watch the output instruction-by-instruction.

Currently, I implemented this only for ARM32 and called it **arm_miniemu**, see it in action:

![arm_miniemu](/static/arm_miniemu.gif)


For each instruction marked, it produces this output:

```console
>>> Tracing instruction at 0x1008, instruction size = 0x4
r0:  0x00000000 r1: 0x00000000 r2:  0x00000000 r3: 0x0000001e
r4:  0x00000000 r5: 0x00000000 r6:  0x00000000 r7: 0xdeadbeef
r8:  0x00000000 r9: 0x00000000 r10: 0x00000000 fp: 0x00080000
r12: 0x00000000 sp: 0x00080000 lr:  0x00000000
-------------------------------------------------------------
pc -> 0x00001008
0x4:	sub	r3, fp, #0xc
-------------------------------------------------------------
sp @ 0x00080000
00 00 00 00 00 00 00 00 00 00 00 1e 00 00 00 00  | sp - 0000
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | sp - 0010
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | sp - 0020
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | sp - 0030
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | sp - 0040
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | sp - 0050
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | sp - 0060
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  | sp - 0070
=============================================================
```

Thus you get a mini emulator in ghidra.

---

Here's the script:

```python
# use unicorn emulator to run code selected in ghidra graphs or listing views
#@author 0xca7
#@category Python 3
#@keybinding 
#@menupath 
#@toolbar 

"""
requires unicorn and capstone to be installed
"""

from unicorn import *
from unicorn.arm_const import *
from capstone import *

"""
constants for emulator
"""
# code starts here
CODE_ADDR = 0x1000
CODE_SIZE = 0x4000

# stack bottom
STACK_ADDR = 0x0007c000
STACK_SIZE = 0x00004000

"""
constant for code hook
"""
# number of stack bytes to print
STACK_PRINT_BYTES = 128


"""
hooks the code being executed. displays all registers, the disassembled instruction and stack
"""
def hook_code(uc, address, size, user_data):

	print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
	
	r0 =   uc.reg_read(UC_ARM_REG_R0)
	r1 =   uc.reg_read(UC_ARM_REG_R1)
	r2 =   uc.reg_read(UC_ARM_REG_R2)
	r3 =   uc.reg_read(UC_ARM_REG_R3)
	r4 =   uc.reg_read(UC_ARM_REG_R4)
	r5 =   uc.reg_read(UC_ARM_REG_R5)
	r6 =   uc.reg_read(UC_ARM_REG_R6)
	r7 =   uc.reg_read(UC_ARM_REG_R7)
	r8 =   uc.reg_read(UC_ARM_REG_R8)
	r9 =   uc.reg_read(UC_ARM_REG_R9)
	r10 =  uc.reg_read(UC_ARM_REG_R10)
	fp =  uc.reg_read(UC_ARM_REG_FP)
	r12 =  uc.reg_read(UC_ARM_REG_R12)
	sp =   uc.reg_read(UC_ARM_REG_SP)
	lr =   uc.reg_read(UC_ARM_REG_LR)
	pc =   uc.reg_read(UC_ARM_REG_PC)

	print('r0:  0x{:08x}'.format(r0), end=' ')
	print('r1: 0x{:08x}'.format(r1), end=' ')
	print('r2:  0x{:08x}'.format(r2), end=' ')
	print('r3: 0x{:08x}'.format(r3))

	print('r4:  0x{:08x}'.format(r4), end=' ')
	print('r5: 0x{:08x}'.format(r5), end=' ')
	print('r6:  0x{:08x}'.format(r6), end=' ')
	print('r7: 0x{:08x}'.format(r7))

	print('r8:  0x{:08x}'.format(r8), end=' ')
	print('r9: 0x{:08x}'.format(r9), end=' ')
	print('r10: 0x{:08x}'.format(r10), end=' ')
	print('fp: 0x{:08x}'.format(fp))

	print('r12: 0x{:08x}'.format(r12), end=' ')
	print('sp: 0x{:08x}'.format(sp), end=' ')
	print('lr:  0x{:08x}'.format(lr))

	print('-------------------------------------------------------------')
	print('pc -> 0x{:08x}'.format(pc))

	code = uc.mem_read(address, size)
	md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	for i in md.disasm(code, size):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

	print('-------------------------------------------------------------')
	# print some stack bytes
	sp = mu.reg_read(UC_ARM_REG_SP)
	print('sp @ 0x{:08x}'.format(sp))
	stack = list(mu.mem_read(sp-STACK_PRINT_BYTES, STACK_PRINT_BYTES))
	stack.reverse()
	lines = 0;
	for (i, byte) in enumerate(stack):
		print('{:02x}'.format(byte), end=' ')
		if (i+1) % 16 == 0:
			print(' | sp - {:04x}'.format(lines * 16))
			lines += 1

	print('=============================================================\n')


"""
main part of the script
"""

reg_select = [
	'r0', 'r1', 'r2', 'r3', 
	'r4', 'r5', 'r6', 'r7',
	'r8', 'r9', 'r10', 'fp',
	'r12', 'sp', 'lr', 'pc',
]

# get the addresses from user selection

codeStart = currentSelection.getMinAddress()
codeEnd = currentSelection.getMaxAddress()

# get the opcodes and data from the area selected
# this part is stolen from Mandiant :) <3
code = bytes(map(lambda b: b & 0xff, getBytes(codeStart, codeEnd.subtract(codeStart) + 1)))

# ask user which regs should be edited
sel = askChoices('sel', 'Choose registers to set:', reg_select)

regs = []

# get values for selected registers
for si in sel:
	s = askString(si, 'enter {} value'.format(si))
	regs.append((si,int(s, base=16)))

# setup the emulator
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

# setup for the code and stack memory
mu.mem_map(CODE_ADDR, CODE_SIZE)
mu.mem_map(STACK_ADDR, STACK_SIZE)

# setup stack
mu.reg_write(UC_ARM_REG_SP, STACK_ADDR+STACK_SIZE)
# setup frame pointer
mu.reg_write(UC_ARM_REG_FP, STACK_ADDR+STACK_SIZE)

# write the code to memory
mu.mem_write(CODE_ADDR, code)

# trace execution
mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDR, end=CODE_ADDR+len(code))

# setup registers, write user supplied values to them
for reg in regs:
	if reg[0] == 'r0':
		mu.reg_write(UC_ARM_REG_R0, reg[1])
	if reg[0] == 'r1':
		mu.reg_write(UC_ARM_REG_R1, reg[1])
	if reg[0] == 'r2':
		mu.reg_write(UC_ARM_REG_R2, reg[1])
	if reg[0] == 'r3':
		mu.reg_write(UC_ARM_REG_R3, reg[1])
	if reg[0] == 'r4':
		mu.reg_write(UC_ARM_REG_R4, reg[1])
	if reg[0] == 'r5':
		mu.reg_write(UC_ARM_REG_R5, reg[1])
	if reg[0] == 'r6':
		mu.reg_write(UC_ARM_REG_R6, reg[1])
	if reg[0] == 'r7':
		mu.reg_write(UC_ARM_REG_R7, reg[1])
	if reg[0] == 'r8':
		mu.reg_write(UC_ARM_REG_R8, reg[1])
	if reg[0] == 'r9':
		mu.reg_write(UC_ARM_REG_R9, reg[1])
	if reg[0] == 'r10':
		mu.reg_write(UC_ARM_REG_R10, reg[1])
	if reg[0] == 'fp':
		mu.reg_write(UC_ARM_REG_FP, reg[1])
	if reg[0] == 'r12':
		mu.reg_write(UC_ARM_REG_R12, reg[1])
	if reg[0] == 'sp':
		mu.reg_write(UC_ARM_REG_SP, reg[1])
	if reg[0] == 'lr':
		mu.reg_write(UC_ARM_REG_LR, reg[1])
	if reg[0] == 'pc':
		mu.reg_write(UC_ARM_REG_PC, reg[1])


mu.emu_start(CODE_ADDR, CODE_ADDR + len(code))

```

# Conclusion

Yeah, it's a work in progress, but I'm only getting into Ghidra scripting :)

# References

[1] https://www.mandiant.com/resources/blog/ghidrathon-snaking-ghidra-python-3-scripting

[2] https://www.unicorn-engine.org/

[3] https://www.capstone-engine.org/
