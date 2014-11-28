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




--------------------------------------------------------------------------------------
--					3X MOVs In A Row 												--
--------------------------------------------------------------------------------------
--Not only are MOVs a common instruction, but movs are also usually found in groups.
--This hueristic is not precise; there would be a significant amount of addressing
--schemes to consider for each mov opcode considering both ModR/M and SIB bytes.
--Using this kind of accuracy would also get potentially lost in the code not beeing
--aligned in the first place. We will assume that a MOV instruction typically never
--exceeds 6 bytes after the opcode (taking into account ModR/M, SIB, and operand). We
--will also consider only 1-byte for a prefix (\x66 \x4X, etc...).
temp_hex_data = data 		--get temporary pad of our data 
local _, count = string.gsub(temp_hex_data, "[\x88\x89\x8a\x8b\x8c\x8e\xa0\xa1\xa2\xa3\xb0\xb8\xc6\xc7]..?.?.?.?.?[\x88\x89\x8a\x8b\x8c\x8e\xa0\xa1\xa2\xa3\xb0\xb8\xc6\xc7]..?.?.?.?.?[\x88\x89\x8a\x8b\x8c\x8e\xa0\xa1\xa2\xa3\xb0\xb8\xc6\xc7]", "")
print("Triple-MOV Instructions: " .. count)

--------------------------------------------------------------------------------------
--					1-Byte Histostat 												--
--------------------------------------------------------------------------------------
--A count of the 
function sortbyvalue(t, order)
    -- collect the keys
    local keys = {}
    for k in pairs(t) do keys[#keys+1] = k end

    table.sort(keys, function(a,b) return order(t, a, b) end)

    -- return the iterator function
    local i = 0
    return function()
        i = i + 1
        if keys[i] then
            return keys[i], t[keys[i]]
        end
    end
end

temp_hex_data = data
local hashed_bytes = {}
for c in temp_hex_data:gmatch"." do
    if hashed_bytes[c] == nil then
    	hashed_bytes[c] = 1
    else
    	hashed_bytes[c] = hashed_bytes[c] + 1
    end
end

print("\nByte Count, per-byte distribution should be " .. math.floor(length/256) .. " count.")
print("Byte","Count","Hint\n-----------------------------------")
for k,v in sortbyvalue(hashed_bytes, function(t,a,b) return t[b] < t[a] end) do
	--create 'hints' for each byte. This is as accurate as it can be considering
	--multibyte ops, prefixes, modifiers, etc... This elseif chain is
	--deliberately placed in the order you see, based on most common bytes first;
	--in order to short-circuit. The most common bytes are based on all binary files
	--from $PATH on Linux-Mint x32 and x64
	if k == "\x00" then hint = "Null or ADD r/m8, r8" formatted_k = "0x00" elseif
	k == "\x48" then hint = "DEC EAX and Common x64 prefix" elseif
	k == "\xFF" then hint = "High-Byte or Possible CALL(r/m16/32/64, m16:16, m16:32, m16:64) or PUSH" elseif
	k == "\x89" then hint = "MOV rm16-32/r16-32" elseif
	k == "\x24" then hint = "AND AL, imm8" elseif	
	k == "\x20" then hint = "AND r/m8, r8 (also ASCII space)" elseif
	k == "\x8B" then hint = "MOV r16,r/m16" elseif
	k == "\xE8" then hint = "CALL rel16/32" elseif	
	k == "\x0F" then hint = "Multi-Byte OpCode" elseif
	k == "\x01" then hint = "ADD r/m16/32/64, r16/32/64" elseif
	k == "\x74" then hint = "JZ (Jump if Zero)" elseif	
	k == "\x65" then hint = "GS: Prefix" elseif	
	k == "\x41" then hint = "INC ECX or x64 prefix" elseif
	k == "\x4C" then hint = "DEC ESP or x64 prefix" elseif
	k == "\x8D" then hint = "LEA (Load Effective Address)" elseif
	k == "\x44" then hint = "INC ESP or x64 prefix" elseif
	k == "\x08" then hint = "OR r/m8, r8" elseif
	k == "\x83" then hint = "SUB, ADD, AND, OR (r/m16/32/64, imm8) or prefix" elseif
	k == "\x85" then hint = "TEST r/m16/32/64, r16/32/64" elseif
	k == "\x72" then hint = "JB (Jump if Below)" elseif
	k == "\x0E" then hint = "\"PUSH CS\"" elseif
	k == "\x6E" then hint = "OUTSB" elseif
	k == "\x02" then hint = "ADD r8, r/m8" elseif
	k == "\x73" then hint = "JNB (Jump if NOT Below)" elseif
	k == "\x69" then hint = "IMUL" elseif
	k == "\xC0" then hint = "ROL, ROR, RCL, RCR, SHL, SHR, SAL, and SAR" elseif
	k == "\x6C" then hint = "INSB" elseif
	k == "\x61" then hint = "\"POPA\"" elseif
	k == "\x10" then hint = "ADC" elseif
	k == "\x6F" then hint = "OUTSW" elseif
	k == "\x5F" then hint = "POP EDI" elseif
	k == "\x84" then hint = "TEST r/m8, r8" elseif
	k == "\x63" then hint = "MOVSXD/(ARPL)" elseif
	k == "\x66" then hint = "8-bit/16-bit \"OPSIZE:\" prefix" elseif
	k == "\x64" then hint = "FS: Prefix" elseif
	k == "\x31" then hint = "XOR" elseif
	k == "\x45" then hint = "INC EBP or x64 prefix" elseif
	k == "\x04" then hint = "ADD AL, imm8" elseif
	k == "\x05" then hint = "ADD AX/EAX/RAX, imm16/32/64" elseif
	k == "\x49" then hint = "DEC ECX or x64 prefix" elseif
	k == "\x75" then hint = "JNZ (Jump if NOT Zero)" elseif
	k == "\x70" then hint = "JO (Jump if Overflow)" elseif
	k == "\x40" then hint = "INC EAX or x64 prefix" elseif
	k == "\x03" then hint = "ADD r16/32/64, r/m16/32/64" elseif
	k == "\xE9" then hint = "JMP" elseif
	k == "\xC7" then hint = "MOV r/m16, imm16" elseif
	k == "\x1F" then hint = "\"POP DS\"" elseif
	k == "\x18" then hint = "SBB" elseif
	k == "\x90" then hint = "NOP" elseif
	k == "\x50" then hint = "PUSH EAX" elseif
	k == "\x28" then hint = "SUB" elseif
	k == "\x30" then hint = "XOR" elseif
	k == "\x0A" then hint = "OR r8, r/m8" elseif
	k == "\x68" then hint = "PUSH immediate word" elseif
	k == "\xFE" then hint = "INC & DEC" elseif
	k == "\xBE" then hint = "MOV ESI" elseif
	k == "\x42" then hint = "INC EDX or x64 prefix" elseif
	k == "\x54" then hint = "PUSH ESP" elseif
	k == "\x2E" then hint = "CS: Prefix" elseif
	k == "\x43" then hint = "INC EBX or x64 prefix" elseif
	k == "\x6D" then hint = "INSD" elseif
	k == "\x80" then hint = "ADD (r/m8, imm8), AND, OR (r/m8, imm8) or prefix" elseif
	k == "\xC3" then hint = "RET" elseif
	k == "\xDF" then hint = "flid, fisttp, fist, fistp, fbld, fild, fbstp, fnstsw, and fucomip" elseif
	k == "\x67" then hint = "ADSIZE: prefix" elseif
	k == "\x53" then hint = "PUSH EBX" elseif
	k == "\x07" then hint = "\"POP\"" elseif
	k == "\x38" then hint = "CMP" elseif
	k == "\xF8" then hint = "CLC" elseif
	k == "\x62" then hint = "\"BOUND\"" elseif
	k == "\xF0" then hint = "LOCK: prefix" elseif
	k == "\x4D" then hint = "DEC EBP or x64 prefix" elseif
	k == "\x7C" then hint = "JL (Jump if Less than)" elseif
	k == "\xF6" then hint = "TEST, NOT, NEG, MUL, IMUL, DIV, and IDIV (r/m8, imm8)" elseif
	k == "\x25" then hint = "AND AX/EAX/RAX, imm16/32" elseif
	k == "\xFD" then hint = "STD" elseif
	k == "\xC4" then hint = "\"LES\"" elseif
	k == "\x5C" then hint = "POP ESP" elseif
	k == "\x06" then hint = "\"PUSH ES\"" elseif
	k == "\x55" then hint = "PUSH EBP" elseif
	k == "\xEB" then hint = "JMP Short 8-bit" elseif
	k == "\xC6" then hint = "MOV r/m8, imm8" elseif
	k == "\x0B" then hint = "OR r16/32/64, r/m16/32/64" elseif
	k == "\x78" then hint = "JS (Jump if Sign bit)" elseif
	k == "\x39" then hint = "CMP" elseif
	k == "\xEF" then hint = "OUT" elseif
	k == "\xE0" then hint = "LOOPNE" elseif
	k == "\x0D" then hint = "OR AX/EAX/RAX, imm16/32" elseif
	k == "\x60" then hint = "\"PUSHA\"" elseif
	k == "\x3D" then hint = "CMP" elseif
	k == "\xBC" then hint = "MOV ESP" elseif
	k == "\x2F" then hint = "\"DAS\"" elseif
	k == "\xBA" then hint = "MOV EDX" elseif
	k == "\xFB" then hint = "STI" elseif
	k == "\x47" then hint = "INC EDI or x64 prefix" elseif
	k == "\x76" then hint = "JBE (Jump if Below or Equal)" elseif
	k == "\xBF" then hint = "MOV EDI" elseif
	k == "\x14" then hint = "ADC" elseif
	k == "\x3A" then hint = "CMP" elseif
	k == "\x12" then hint = "ADC" elseif
	k == "\x4E" then hint = "DEC ESI or x64 prefix" elseif
	k == "\xFC" then hint = "CLD" elseif
	k == "\xC1" then hint = "ROL, ROR, RCL, RCR, SHL, SHR, SAL, and SAR" elseif
	k == "\x35" then hint = "XOR" elseif
	k == "\xD0" then hint = "ROL, ROR, RCL, RCR, SHL, SHR, SAL, and SAR" elseif
	k == "\xD2" then hint = "ROL, ROR, RCL, RCR, SHL, SHR, SAL, and SAR" elseif
	k == "\x0C" then hint = "OR AL, imm8" elseif
	k == "\xEC" then hint = "IN" elseif
	k == "\x15" then hint = "ADC" elseif
	k == "\x2D" then hint = "SUB" elseif
	k == "\x52" then hint = "PUSH EDX" elseif
	k == "\x29" then hint = "SUB" elseif
	k == "\x79" then hint = "JNS (Jump if NOT Signed)" elseif
	k == "\xB8" then hint = "MOV EAX" elseif
	k == "\x5B" then hint = "POP EBX" elseif
	k == "\xF2" then hint = "REPNE: Prefix" elseif
	k == "\x09" then hint = "OR r/m16/32/64, r16/32/64" elseif
	k == "\xB6" then hint = "MOV DH" elseif
	k == "\xC2" then hint = "RETN" elseif
	k == "\x2C" then hint = "SUB" elseif
	k == "\x77" then hint = "JA (Jump if Above)" elseif
	k == "\x58" then hint = "POP EAX" elseif
	k == "\x5D" then hint = "POP EBP" elseif
	k == "\xC5" then hint = "\"LDS\"" elseif
	k == "\x6B" then hint = "IMUL" elseif
	k == "\x3B" then hint = "CMP" elseif
	k == "\xFA" then hint = "CLI" elseif
	k == "\x86" then hint = "XCHG" elseif
	k == "\x46" then hint = "INC ESI or x64 prefix" elseif
	k == "\x88" then hint = "MOV r/m8,r8" elseif
	k == "\xED" then hint = "IN" elseif
	k == "\x1C" then hint = "SBB" elseif
	k == "\xA0" then hint = "MOV AL, moffs8" elseif
	k == "\x4F" then hint = "DEC EDI or x64 prefix" elseif
	k == "\x34" then hint = "XOR" elseif
	k == "\x8C" then hint = "MOV r/m16, Sreg" elseif
	k == "\x3C" then hint = "CMP" elseif
	k == "\xB0" then hint = "MOV r8, imm8" elseif
	k == "\xE7" then hint = "OUT" elseif
	k == "\xF7" then hint = "TEST, NOT, NEG, MUL, IMUL, DIV, and IDIV (r/m15/32/64, imm16/32)" elseif
	k == "\xD8" then hint = "FADD, FMUL, FCOM, FCOMP, FSUB, FSUBR, FDIV, and FDIVR" elseif
	k == "\x32" then hint = "XOR" elseif
	k == "\xEE" then hint = "OUT" elseif
	k == "\x22" then hint = "AND r8, r/m8" elseif
	k == "\xC9" then hint = "LEAVE" elseif
	k == "\x11" then hint = "ADC" elseif
	k == "\x81" then hint = "ADD, AND, OR (r/m16/32/64, imm16/32/64) or prefix" elseif
	k == "\x7B" then hint = "JNP (Jump if NOT Parity)" elseif
	k == "\x57" then hint = "PUSH EDI" elseif
	k == "\x27" then hint = "\"DAA\"" elseif
	k == "\xF9" then hint = "STC" elseif
	k == "\xF3" then hint = "REP: Prefix" elseif
	k == "\x33" then hint = "XOR" elseif
	k == "\xB9" then hint = "MOV ECX" elseif
	k == "\xC8" then hint = "ENTER" elseif
	k == "\x7D" then hint = "JNL (Jump if NOT Lower than)" elseif
	k == "\xE4" then hint = "IN" elseif
	k == "\x21" then hint = "AND r/m32, r32" elseif
	k == "\x4B" then hint = "DEC EBX or x64 prefix" elseif
	k == "\xE6" then hint = "OUT" elseif
	k == "\xEA" then hint = "\"JMP\"" elseif
	k == "\x94" then hint = "XCHG" elseif
	k == "\xB4" then hint = "MOV AH" elseif
	k == "\xF5" then hint = "CMC" elseif
	k == "\x56" then hint = "PUSH ESI" elseif
	k == "\x36" then hint = "SS: Prefix" elseif
	k == "\xE2" then hint = "LOOP" elseif
	k == "\xDB" then hint = "FILD, FISTTP, FIST, FISTP, FLD, FSTP, FCMOVNB, FCMOVNE, FCMOVNBE, FCMOVNU, FNENI, FNDISI, FNCLEX, FNINIT, FNSETPM, and FUCOMI" elseif
	k == "\x4A" then hint = "DEC EDX or x64 prefix" elseif
	k == "\x98" then hint = "CWDE" elseif
	k == "\xF4" then hint = "HLT" elseif
	k == "\xA8" then hint = "TEST AL, imm8" elseif
	k == "\x37" then hint = "\"AAA\"" elseif
	k == "\x23" then hint = "AND r16/32/64, r/m16/32/64" elseif
	k == "\x8E" then hint = "MOV Sreg, r/m16" elseif
	k == "\xDE" then hint = "FIADD, FIMUL, FICOM, FICOMP, FISUB, FISUBR, FIDIV, FIDIVR, FADDP, FMULP, FCOMPP, FSUBRP, FSUBP, FDIVRP, and FDIVP" elseif
	k == "\x5A" then hint = "POP EDX" elseif
	k == "\x13" then hint = "ADC" elseif
	k == "\x95" then hint = "XCHG" elseif
	k == "\x51" then hint = "PUSH ECX" elseif
	k == "\x3E" then hint = "DS: Prefix" elseif
	k == "\x2A" then hint = "SUB" elseif
	k == "\x7F" then hint = "JNLE (Jump if NOT Less than or Equal)" elseif
	k == "\x59" then hint = "POP ECX" elseif
	k == "\x8F" then hint = "POP" elseif
	k == "\xE5" then hint = "IN" elseif
	k == "\xF1" then hint = "\"INT1\"" elseif
	k == "\x2B" then hint = "SUB" elseif
	k == "\x5E" then hint = "POP ESI" elseif
	k == "\xD1" then hint = "ROL, ROR, RCL, RCR, SHL, SHR, SAL, and SAR" elseif
	k == "\xBB" then hint = "MOV EBX" elseif
	k == "\x26" then hint = "ES: Prefix" elseif
	k == "\xD5" then hint = "\"AAD\"" elseif
	k == "\x17" then hint = "\"POP SS\"" elseif
	k == "\xB7" then hint = "MOV BH" elseif
	k == "\x1D" then hint = "SBB" elseif
	k == "\x16" then hint = "\"PUSH SS\"" elseif
	k == "\x19" then hint = "SBB" elseif
	k == "\x7E" then hint = "JLE (Jump if Lower than or Equal)" elseif
	k == "\xE1" then hint = "LOOPE" elseif
	k == "\x7A" then hint = "JP (Jump if Parity)" elseif
	k == "\xD6" then hint = "\"SALC\"" elseif
	k == "\xDA" then hint = "FIADD, FIMUL, FICOM, FICOMP, FISUB, FISUBR, FIDIV, FIDIVR, FCMOVB, FCMOVE, FCMOVBE, FCMOVU, and FUCOMPP" elseif
	k == "\xD4" then hint = "\"AAM\"" elseif
	k == "\x71" then hint = "JNO (Jump if NOT Overflow)" elseif
	k == "\xAC" then hint = "LODSB" elseif
	k == "\xCC" then hint = "INT3" elseif
	k == "\x87" then hint = "XCHG" elseif
	k == "\x3F" then hint = "\"AAS\"" elseif
	k == "\x9C" then hint = "PUSHF" elseif
	k == "\x1A" then hint = "SBB" elseif
	k == "\xCA" then hint = "RETF" elseif
	k == "\x6A" then hint = "PUSH immediate byte" elseif
	k == "\xE3" then hint = "JRCXZ" elseif
	k == "\xDC" then hint = "FADD, FMUL, FCOM, FCOMP, FSUB, FSUBR, FDIV, FDIVR" elseif
	k == "\x1E" then hint = "\"PUSH DS\"" elseif
	k == "\x1B" then hint = "SBB" elseif
	k == "\xBD" then hint = "MOV EBP" elseif
	k == "\xD3" then hint = "ROL, ROR, RCL, RCR, SHL, SHR, SAL, and SAR" elseif
	k == "\xD7" then hint = "XLAT" elseif
	k == "\xD9" then hint = "FLD, FST, FSTP, FLDENV, FLDCW, FNSTENV, FNSTCW, FXCH, FNOP, FCHS, FABS, FTST, FXAM, FLDL, FLDL2T, FLDL2E, FLDPI, FLDLG2, FLDLN2, FLDZ, F2XM1, FYL2X, FPTAN, FPATAN, FXTRACT, FPREM1, FDECSTP, FINCSTP, FPREM, FYL2XP1, FSQRT, FSINCOS, FRNDINT, FSCALE, FSIN, and FCOS" elseif
	k == "\xA4" then hint = "MOVSB" elseif
	k == "\xCE" then hint = "\"INTO\"" elseif
	k == "\xCD" then hint = "INT" elseif
	k == "\xDD" then hint = "FLD, FISTTP, FST, FSTP, FRSTOR, FNSAVE, FNSTSW, FFREE, FUCOM, FUCOMP, " elseif
	k == "\x82" then hint = "\"SUB\"" elseif
	k == "\xA6" then hint = "CMPSB" elseif
	k == "\xCF" then hint = "IRET" elseif
	k == "\xAB" then hint = "STOSD" elseif
	k == "\xAF" then hint = "SCASD" elseif
	k == "\xAA" then hint = "STOSB" elseif
	k == "\xCB" then hint = "RETF" elseif
	k == "\xA9" then hint = "TEST AX/EAX, imm16/32" elseif
	k == "\x93" then hint = "XCHG" elseif
	k == "\xB3" then hint = "MOV BL" elseif
	k == "\xB5" then hint = "MOV CH" elseif
	k == "\x92" then hint = "XCHG" elseif
	k == "\xA3" then hint = "MOV moffs 16, AX" elseif
	k == "\x96" then hint = "XCHG" elseif
	k == "\xA2" then hint = "MOV moffs8, AL" elseif
	k == "\x97" then hint = "XCHG" elseif
	k == "\xB2" then hint = "MOV DL" elseif
	k == "\xA7" then hint = "CMPSD" elseif
	k == "\xB1" then hint = "MOV CL" elseif
	k == "\x8A" then hint = "MOV r8,r/m8" elseif
	k == "\x91" then hint = "XCHG" elseif
	k == "\xAD" then hint = "LODSD" elseif
	k == "\x99" then hint = "CDQ" elseif
	k == "\xA1" then hint = "MOV AX/EAX, moffs16/32" elseif
	k == "\x9B" then hint = "WAIT" elseif
	k == "\x9A" then hint = "CALL ptr16:16/16:32" elseif
	k == "\xAE" then hint = "SCASB" elseif
	k == "\x9D" then hint = "POPFD" elseif
	k == "\xA5" then hint = "MOVSD" elseif
	k == "\x9F" then hint = "LAHF" elseif
	k == "\x9E" then hint = "SAHF" end		
	formatted_k = string.format('0x%02X ',string.byte(k))
    print(formatted_k,v,hint)
end

temp_hex_data = data 		--get temporary pad of our data 
op_count = 0 				--reusable count per (complicated) op
local calls = 0
local rets = 0
local popreg = 0
local _, count = string.gsub(temp_hex_data, "[\x88\x89\x8a\x8b\x8c\x8e\xa0\xa1\xa2\xa3\xb0\xb8\xc6\xc7]", "")
print("MOV opcodes: " .. count)
local _, count = string.gsub(temp_hex_data, "[\xe8\x9a]", "")
op_count = count
local _, count = string.gsub(temp_hex_data, "\xff[\x10-\x1f\x50-\x5f\x90-\x9f\xd0-\xdf]", "")
op_count = op_count + count
calls = op_count
print("CALL opcodes: " .. op_count)
op_count = 0
local _, count = string.gsub(temp_hex_data, "[\x50-\x57\x6A\x68]", "")
op_count = count
local _, count = string.gsub(temp_hex_data, "\xff[\x30-\x37\x70-\x77\xb0-\xb7\xf0-\xf7]", "")
op_count = op_count + count
print("PUSH opcodes: " .. op_count)
op_count = 0
local _, count = string.gsub(temp_hex_data, "[\x58-\x5f]", "")
op_count = count
popreg = op_count
local _, count = string.gsub(temp_hex_data, "\x8f[\x00-\x07\x40-\x47\x80-\x87\xc0-\xc7]", "")
op_count = op_count + count
print("POP opcodes: " .. op_count)
op_count = 0
local _, count = string.gsub(temp_hex_data, "[\x3c\x3d\x38\x39\x3a\x3b]", "")
op_count = count
local _, count = string.gsub(temp_hex_data, "[\x80\x81\x83][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff]", "")
op_count = op_count + count
print("CMP opcodes: " .. op_count)
op_count = 0
local _, count = string.gsub(temp_hex_data, "\x90", "")
print("NOPs: " .. count)
local _, count = string.gsub(temp_hex_data, "\xcd\x80", "")
print("INT 80s: " .. count)
local _, count = string.gsub(temp_hex_data, "\xcd\x21", "")
print("INT 21s: " .. count)
local _, count = string.gsub(temp_hex_data, "[\xc3\xcb\xc2\xca]", "")
rets = count


--------------------------------------------------------------------------------------
--					Call/RET Ballance												--
--------------------------------------------------------------------------------------
--Data already harvested from histogram routines
print("\n\nCALLs: " .. calls .. "\nRETs: " .. rets)

--------------------------------------------------------------------------------------
--					POP->RET Combo													--
--------------------------------------------------------------------------------------
print("\n\nPOPs: " .. popreg)
print("RETs: " .. rets)
local _, count = string.gsub(temp_hex_data, "[\x58-\x5f][\xc3\xcb\xc2\xca]", "")
local poprets = count
print("POP->RETs: " .. poprets)

--Documentation of Hueristics
--[[
xor reg, reg (DONE):
	Compilers typically xor a register with itself to set the register to 0.
	Prefixes asside, this translates to a 2 byte instruction, instead, for
	example, a 5 byte mov eax, 0.

Triple Mov (Working):
	MOV is a very common instruction. It is also very common for mov's to
	occur in groups. This hueristic would look for any case of 3 mov's in
	a row

Some one-byte histogram stuff (In Progress):
	The 6 most common assembly instructions (accounting for more than half 
	of instructions actually used) are mov, push, call, pop, cmp, and nop.
	Nulls happen to occur frequently in machine code too (very frequently
	in operands). This heuristic may not be as strong as others.

CALL/RET Balance (DONE):
	There may be more (maybe much more) Calls than Rets, but the inverse 
	probably shouldn't be true.

Pop->Ret  (DONE):
	This may be compiler specific, but a Ret is typically preceded by a pop
	to a register

condition_test -> conditional_jmp:
	This is pretty obvious; if the code is going to do a conditional jump,
	it would make sense for there to be a conditional test preceding it.
	This may be one of the higher fidelity hueristics here

Enumeration of some cmp machine instructions and its variations
	cmp al, imm8		3c XX

	cmp ax, imm16		66 3d XX XX
	cmp eax, imm32		3d XX XX XX XX
	cmp rax, imm32		4X 3d XX XX XX XX

	cmp r/m8, imm8		80 F[8-F] XX			(F8, F9, FA ..etc is al, cl, dl, respectively)

	cmp r/m16, imm16	66 81 F[8-F] XX XX		66 is prefix for 16-bit
	cmp r/32, imm32		81 F[8-F] XX XX XX XX
	cmp r/64, imm32		48 81 F[8-F] XX XX XX XX	48 is 64-bit register prefix

	cmp r/m,imm8		66? 48? 83 F[8-F] XX
	cmp r/m8, r8		48? 38 XX
	cmp r/m, r			66? 48? 39 XX
	cmp r8, r/m8 		3a XX
	cmp r, r/m 			66? 48? 3b XX
--]]
