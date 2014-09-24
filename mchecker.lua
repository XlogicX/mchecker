#!/usr/bin/lua

local FILE = (io.open(arg[1], "rb"))	--Open our suspect file (read/binary-mode)
local data = FILE:read("*all")			--Get all of the data into a scalar
local length = string.len(data)			--Compute length of file

--------------------------------------------------------------------------------------
--					XOR REGISTER with ITSELF HUERISTIC								--
--------------------------------------------------------------------------------------
--Checking for XOR Reg, Reg (around 200+ variations)
--The pattern matching is very unreadable, so I will explain:
--There are 4 main opcodes that support 'xor reg, reg'; 30, 31, 32, and 33
--	In ASCII this is just 0, 1, 2, and 3, So I used a character class of [0123]
--There are only 8 operand bytes that represent the same register for src and dst:
--	c0, db, c9, d2, ed, e4, f6, and ff
--Instructions can have prefixes, this can hurt us with false positives if not handled;
--  For instance: 31 c0 is just an xor eax, eax, the prefix of 48 (48 31 c0) gives us xor rax, rax.
--	This is also fine. But a prefix of 46 for example (46 31 c0) would give us xor eax, r8d, this
-- 	is not what we are looking for. Also consider the 8/16-bit 66 prefix (66 31 c0), which is
--	xor ax, ax (also acceptable). Instead of enumerating good prefixes, we do a character class of
--	'bad' ones. We don't want 41, 43, 44, 46, 49, 4b, 4c, or 4e, doing the same ASCII
--	representation gives us a negated character class of [^ACDFIKLN].
--Overlap
--	There are many machine-code instructions that translate to identical high-level
--	Assembly instructions. This is accounted for.
local temp_hex_data = data 		--get temporary pad of our data 
local xor = {}
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN][0123]\xc0", "")
xor[0] = count
print(count .. "\txor al/ax/eax/rax/r8b/r8d/r8 with itself")
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN][0123]\xdb", "")
print(count .. "\txor bl/bx/ebx/rbx/r11b/r11d/r11 with itself")
xor[1] = count
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN][0123]\xc9", "")
print(count .. "\txor cl/cx/ecx/rcx/r9b/r9d/r9 with itself")
xor[2] = count
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN][0123]\xd2", "")
print(count .. "\txor dl/dx/edx/rdx/r10b/r10d/r10 with itself")
xor[3] = count
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN][0123]\xed", "")
print(count .. "\txor ch/bp/bpl/ebp/rbp/r13b/r13d/r13 with itself")
xor[4] = count
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN][0123]\xe4", "")
print(count .. "\txor ah/sp/spl/esp/rsp/r12b/r12d/r12 with itself")
xor[5] = count
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN][0123]\xf6", "")
print(count .. "\txor dh/si/sil/esi/rsi/r14b/r14d/r14 with itself")
xor[6] = count
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN][0123]\xff", "")
print(count .. "\txor bh/di/dil/edi/rdi/r15b/r15d/r15 with itself")
xor[7] = count

--Get total instances of xor reg, reg
local count = 0
local total_xor = 0
for count = 0, 7 do
	total_xor = total_xor + xor[count]
end

print(total_xor .. "\tTotal xor reg, reg")

print("\nStatistics:")
print("File Size: " .. length .. " bytes")
print("xor reg, reg to byte ratio: " .. total_xor/length)
print("Accumulator Register to Total Registers ratio: " .. xor[0] / total_xor)

--Get entropy
local entropy = 0
for count = 0, 7 do
	xor[count] = xor[count] / total_xor
	xor[count] = xor[count] * math.log(xor[count])
	entropy = entropy + xor[count]
end
entropy = math.abs(entropy / math.log(2))
print("Entropy is: " .. entropy)





--Documentation of Hueristics
--[[
xor reg, reg (DONE):
	Compilers typically xor a register with itself to set the register to 0.
	Prefixes asside, this translates to a 2 byte instruction, instead, for
	example, a 5 byte mov eax, 0.

Triple Mov:
	MOV is a very common instruction. It is also very common for mov's to
	occur in groups. This hueristic would look for any case of 3 mov's in
	a row

Some one-byte histogram stuff:
	The 6 most common assembly instructions (accounting for more than half 
	of instructions actually used) are mov, push, call, pop, cmp, and nop.
	Nulls happen to occur frequently in machine code too (very frequently
	in operands). This heuristic may not be as strong as others.

Pop->Ret:
	This may be compiler specific, but a Ret is typically preceded by a pop
	to a register

Add rsp, 0xhex -> Ret:
	This also may be compiler specific, but when the above Pop->Ret pattern
	isn't the case, this is usually what exists instead

condition_test -> conditional_jmp:
	This is pretty obvious; if the code is going to do a conditional jump,
	it would make sense for there to be a conditional test preceding it.
	This may be one of the higher fidelity hueristics here

Enumeration of some cmp machine instructions and its variations
	cmp al, imm8		3c XX

	cmp ax, imm16		66 3d XX XX
	cmp eax, imm32		3d XX XX XX XX
	cmp rax, imm32		48 3d XX XX XX XX

	cmp r/m8, imm8		80 F[8-F] XX			(F8, F9, FA ..etc is al, cl, dl, respectively)

	cmp r/m16, imm16	66 81 F[8-F] XX XX		66 is prefix for 16-bit
	cmp r/32, imm32		81 F[8-F] XX XX XX XX
	cmp r/64, imm32		48 81 F[8-F] XX XX XX XX	48 is 64-bit register prefix

	cmp r/m,imm8		66? 48? 83 F[8-F] XX
	cmp r/m8, r8		48? 38 XX
	cmp r/m, r			66? 48? 39 XX
	cmp r8, r/m8 		3a XX
	cmp r, r/m 			66? 48? 3b XX

Enumeration of some mov machine instructions and its variations
88 [0123]X
88 [4567]X XX
88 [89ab]X
88 [cdef]X
--]]
