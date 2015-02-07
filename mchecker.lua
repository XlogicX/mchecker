#!/usr/bin/lua

local FILE = (io.open(arg[1], "rb"))	--Open our suspect file (read/binary-mode)
local data = FILE:read("*all")			--Get all of the data into a scalar
local length = string.len(data)			--Compute length of file

local fverdict = 0

--Threshholds
local fences_t = 5000	--lower than this is not code, higher is ambiguous

--This GetOpt function from: lua-users.org/wiki/AlternativeGetOpt
function getopt( arg, options )
  local tab = {}
  for k, v in ipairs(arg) do
    if string.sub( v, 1, 2) == "--" then
      local x = string.find( v, "=", 1, true )
      if x then tab[ string.sub( v, 3, x-1 ) ] = string.sub( v, x+1 )
      else      tab[ string.sub( v, 3 ) ] = true
      end
    elseif string.sub( v, 1, 1 ) == "-" then
      local y = 2
      local l = string.len(v)
      local jopt
      while ( y <= l ) do
        jopt = string.sub( v, y, y )
        if string.find( options, jopt, 1, true ) then
          if y < l then
            tab[ jopt ] = string.sub( v, y+1 )
            y = l
          else
            tab[ jopt ] = arg[ k + 1 ]
          end
        else
          tab[ jopt ] = true
        end
        y = y + 1
      end
    end
  end
  return tab
end

--[[
-v verbose
-r give ratios
-d give code/not-code/unsure details
--]]
opts = getopt( arg, "" )

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
--	representation gives us a negated character class of [^ACDFIKLN]. Also the 0F Multibyte
--  sequence has some valid ops that start with 0x3X
--Overlap
--	There are many machine-code instructions that translate to identical high-level
--	Assembly instructions. This is accounted for.
local temp_hex_data = data 		--get temporary pad of our data 
local xor = {}
local _, count = string.gsub(temp_hex_data, "[^ACDFIKLN\x0f][0123]\xc0", "")
xor[0] = count
if opts["v"] == true then print(count .. "\txor al/ax/eax/rax/r8b/r8d/r8 with itself") end
_, count = string.gsub(temp_hex_data, "[^ACDFIKLN\x0f][0123]\xdb", "")
if opts["v"] == true then print(count .. "\txor bl/bx/ebx/rbx/r11b/r11d/r11 with itself") end
xor[1] = count
_, count = string.gsub(temp_hex_data, "[^ACDFIKLN\x0f][0123]\xc9", "")
if opts["v"] == true then print(count .. "\txor cl/cx/ecx/rcx/r9b/r9d/r9 with itself") end
xor[2] = count
_, count = string.gsub(temp_hex_data, "[^ACDFIKLN\x0f][0123]\xd2", "")
if opts["v"] == true then print(count .. "\txor dl/dx/edx/rdx/r10b/r10d/r10 with itself") end
xor[3] = count
_, count = string.gsub(temp_hex_data, "[^ACDFIKLN\x0f][0123]\xed", "")
if opts["v"] == true then print(count .. "\txor ch/bp/bpl/ebp/rbp/r13b/r13d/r13 with itself") end
xor[4] = count
_, count = string.gsub(temp_hex_data, "[^ACDFIKLN\x0f][0123]\xe4", "")
if opts["v"] == true then print(count .. "\txor ah/sp/spl/esp/rsp/r12b/r12d/r12 with itself") end
xor[5] = count
_, count = string.gsub(temp_hex_data, "[^ACDFIKLN\x0f][0123]\xf6", "")
if opts["v"] == true then print(count .. "\txor dh/si/sil/esi/rsi/r14b/r14d/r14 with itself") end
xor[6] = count
_, count = string.gsub(temp_hex_data, "[^ACDFIKLN\x0f][0123]\xff", "")
if opts["v"] == true then print(count .. "\txor bh/di/dil/edi/rdi/r15b/r15d/r15 with itself") end
xor[7] = count

--Get total instances of xor reg, reg
local count = 0
local total_xor = 0
for count = 0, 7 do
	total_xor = total_xor + xor[count]
end

if opts["v"] == true then print(total_xor .. "\tTotal xor reg, reg") end

if opts["v"] == true then print("\nStatistics:") end
if opts["v"] == true then print("File Size: " .. length .. " bytes") end
if opts["r"] == true then print("xor reg, reg to byte ratio: " .. (total_xor/length) * 100) end
--Confidence checking
if ((total_xor/length) * 100 > .1) and ((total_xor/length) * 100 < .2) then
	fverdict = fverdict + .1
	if opts["d"] == true then print ("XOR reg, reg: maybe code") end
elseif ((total_xor/length) * 100 > .2) and ((total_xor/length) * 100 < .4) then
	fverdict = fverdict + 1
	if opts["d"] == true then print ("XOR reg, reg: probably code") end
elseif ((total_xor/length) * 100 > .4) then
	fverdict = fverdict + 2
	if opts["d"] == true then print ("XOR reg, reg: very likely code") end	
else 
	fverdict = fverdict - .1
	if opts["d"] == true then print ("XOR reg, reg: unlikely code") end
end

if opts["r"] == true then print("Accumulator Register to Total Registers ratio: " .. (xor[0] / total_xor) * 100) end
--Confidence checking
if ((xor[0] / total_xor) * 100 > 20) and ((xor[0] / total_xor) * 100 < 40) then
	fverdict = fverdict + .1
	if opts["d"] == true then print ("XOR A vs X: maybe code") end
elseif ((xor[0] / total_xor) * 100 > 40) and ((xor[0] / total_xor) * 100 < 120) then
	fverdict = fverdict + 1
	if opts["d"] == true then print ("XOR A vs X: probably code") end
else 
	fverdict = fverdict - .1
	if opts["d"] == true then print ("XOR A vs X: unlikely code") end
end


--Get entropy
local entropy = 0
for count = 0, 7 do
	xor[count] = xor[count] / total_xor
	xor[count] = xor[count] * math.log(xor[count])
	entropy = entropy + xor[count]
end
entropy = math.abs(entropy / math.log(2))
if opts["r"] == true then print("Entropy is: " .. entropy) end
--Confidence checking
if ((entropy > 2) and (entropy < 2.7)) then
	fverdict = fverdict + 1
	if opts["d"] == true then print ("entropy: probably code") end
elseif ((entropy > 1.5) and (entropy < 2)) then
	fverdict = fverdict + .1
	if opts["d"] == true then print ("entropy: maybe code") end
elseif (entropy > 2.9) then
	fverdict = fverdict - 2
	if opts["d"] == true then print ("entropy: very unlikely to be code") end	
else 
	fverdict = fverdict - .1
	if opts["d"] == true then print ("entropy: unlikely code") end
end

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

if opts["v"] == true then print("\nByte Count, per-byte distribution should be " .. math.floor(length/256) .. " count.") end
if opts["v"] == true then print("Byte","Count","Hint\n-----------------------------------") end
for k,v in sortbyvalue(hashed_bytes, function(t,a,b) return t[b] < t[a] end) do
	--create 'hints' for each byte. This is as accurate as it can be considering
	--multibyte ops, prefixes, modifiers, etc... This elseif chain is
	--deliberately placed in the order you see, based on most common bytes first;
	--in order to short-circuit. The most common bytes are based on all binary files
	--from /usr/bin on an ubuntu system.
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
    if opts["v"] == true then print(formatted_k,v,hint) end
end

temp_hex_data = data 		--get temporary pad of our data 
op_count = 0 				--reusable count per (complicated) op
local calls = 0
local rets = 0
local popreg = 0
_, count = string.gsub(temp_hex_data, "[\x88\x89\x8a\x8b\x8c\x8e\xa0\xa1\xa2\xa3\xb0\xb8\xc6\xc7]", "")
if opts["v"] == true then print("MOV opcodes: " .. count) end
_, count = string.gsub(temp_hex_data, "[^\x0f][\xe8\x9a]", "")
op_count = count
_, count = string.gsub(temp_hex_data, "[^\xd9]\xff[\x10-\x1f\x50-\x5f\x90-\x9f\xd0-\xdf]", "")
op_count = op_count + count
calls = op_count
if opts["v"] == true then print("CALL opcodes: " .. op_count) end
op_count = 0
_, count = string.gsub(temp_hex_data, "[^\x0f][\x50-\x57\x6A\x68]", "")
op_count = count
_, count = string.gsub(temp_hex_data, "[^\xd9]\xff[\x30-\x37\x70-\x77\xb0-\xb7\xf0-\xf7]", "")
op_count = op_count + count
if opts["v"] == true then print("PUSH opcodes: " .. op_count) end
op_count = 0
_, count = string.gsub(temp_hex_data, "[^\x0f][\x58-\x5f]", "")
op_count = count
popreg = op_count
_, count = string.gsub(temp_hex_data, "[^\x0f]\x8f[\x00-\x07\x40-\x47\x80-\x87\xc0-\xc7]", "")
op_count = op_count + count
if opts["v"] == true then print("POP opcodes: " .. op_count) end
op_count = 0
_, count = string.gsub(temp_hex_data, "[^\x0f][\x3c\x3d\x38\x39\x3a\x3b]", "")
op_count = count
_, count = string.gsub(temp_hex_data, "[\x80\x81\x83][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff]", "")
op_count = op_count + count
if opts["v"] == true then print("CMP opcodes: " .. op_count) end
op_count = 0
_, count = string.gsub(temp_hex_data, "[^\x0F\xF3]\x90", "")
if opts["v"] == true then print("NOPs: " .. count) end
_, count = string.gsub(temp_hex_data, "\xcd\x80", "")
if opts["v"] == true then print("INT 80s: " .. count) end
_, count = string.gsub(temp_hex_data, "\xcd\x21", "")
if opts["v"] == true then print("INT 21s: " .. count) end
_, count = string.gsub(temp_hex_data, "[^\x0f\x01][\xc3\xcb\xc2\xca]", "")
rets = count


--------------------------------------------------------------------------------------
--					Call/RET Ballance												--
--------------------------------------------------------------------------------------
--Data already harvested from histogram routines
if opts["v"] == true then print("\n\nCALLs: " .. calls .. "\nRETs: " .. rets) end

--Getting Ratios
local callret_r = calls / rets
if opts["r"] == true then print("Call/RET Ratio: " .. callret_r) end

--Confidence checking
if ((callret_r > 2) and (callret_r < 6)) then
	fverdict = fverdict + 1
	if opts["d"] == true then print ("Call->Ret: very likely code") end
elseif ((callret_r > 1) and (callret_r < 2)) then
	fverdict = fverdict + .1
	if opts["d"] == true then print ("Call->Ret: maybe code") end
elseif (callret_r < 1) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("Call->Ret: unlikely to be code") end	
else 
	fverdict = fverdict - .1
	if opts["d"] == true then print ("Call->Ret: unlikely to be code") end
end

--------------------------------------------------------------------------------------
--					POP->RET Combo													--
--------------------------------------------------------------------------------------
if opts["v"] == true then print("\n\nPOPs: " .. popreg) end
if opts["v"] == true then print("RETs: " .. rets) end
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x58-\x5f][\xc3\xcb\xc2\xca]", "")
local poprets = count
if opts["v"] == true then print("POP->RETs: " .. poprets) end

--Getting Ratios
local pop_r = (popreg / length) * 100
local ret_r = (rets / length) * 100
local popret_r = (poprets / length) * 100
if opts["r"] == true then print("Pop Ratio: " .. pop_r) end
if opts["r"] == true then print("Ret Ratio: " .. ret_r) end
if opts["r"] == true then print("Pop->Ret Ratio: " .. popret_r) end

--Confidence checking
if ((pop_r > .01) and (pop_r < 2)) then
	fverdict = fverdict + .5
	if opts["d"] == true then print ("POP ratio: likely code") end
elseif (pop_r > 4) then
	fverdict = fverdict - .5
	if opts["d"] == true then print ("POP ratio: unlikely code") end	
else 
	if opts["d"] == true then print ("POP ratio: unsure") end
end

--Confidence checking
if ((ret_r > .05) and (ret_r < 1)) then
	fverdict = fverdict + .5
	if opts["d"] == true then print ("Ret ratio: likely code") end
elseif (ret_r > 1.3) then
	fverdict = fverdict - .5
	if opts["d"] == true then print ("Ret ratio: unlikely code") end	
else 
	fverdict = fverdict - .1
	if opts["d"] == true then print ("Ret ratio: unlikely code") end
end

--Confidence checking
if ((popret_r > .06) and (popret_r < 1)) then
	fverdict = fverdict + .5
	if opts["d"] == true then print ("Pop->Ret: probably code") end
elseif ((popret_r > .1) and (popret_r < .15)) then
	fverdict = fverdict + .8
	if opts["d"] == true then print ("Pop->Ret: likely code") end
elseif (popret_r > .15) then
	fverdict = fverdict + 1
	if opts["d"] == true then print ("Pop->Ret: very likely code") end	
else 
	fverdict = fverdict - .1
	if opts["d"] == true then print ("Pop->Ret: unlikely to be code") end
end

--------------------------------------------------------------------------------------
--					TEST/CMP -> Jcc													--
--------------------------------------------------------------------------------------
--Simplifications were made when considering the ModR/M and SIB bytes of the TEST or
--CMP. the 'none' SIB option was never considered, and the need for a SIB byte
--indicated by the ModR/M was used only for some machine-code implementations. All of
--these choices were decided by the frequency actually used in observation of real
--compiled/assembled machine code.
if opts["v"] == true then print("\n\nConditions with Checks: ") end
--Jcc's (that would work with TEST)
_, count = string.gsub(temp_hex_data, "[^\x0f][\x74\x75\x78\x79\x7a\x7b\x7f]", "")
local testjccs = count
_, count = string.gsub(temp_hex_data, "[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "")
testjccs = testjccs + count
if opts["v"] == true then print("Jcc's (that would have preceding TEST): " .. testjccs) end

--TEST -> Jcc
_, count = string.gsub(temp_hex_data, "[^\x38\x0f][\xa8].[\x74\x75\x78\x79\x7a\x7b\x7f]", "") --Test(a8) -> Jcc
local tests = count
_, count = string.gsub(temp_hex_data, "[^\x38\x0f][\xa8].[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "") --Test(a8) -> OF Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^\x66\x38\x0f][\xa9]....[\x74\x75\x78\x79\x7a\x7b\x7f]", "") --test(a9) -> Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^\x66\x38\x0f][\xa9]....[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "") --test(a9) -> OF Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[66][\xa9]..[\x74\x75\x78\x79\x7a\x7b\x7f]", "") --test(66 a9) -> Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[66][\xa9]..[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "") --test (66 a9) -> OF Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^\x38\x0f][\xf6][\x00-\x07\x40-\x47\x80-\x87\xc0-\xc7].[\x74\x75\x78\x79\x7a\x7b\x7f]", "") --test(f6 /0) -> Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^\x38\x0f][\xf6][\x00-\x07\x40-\x47\x80-\x87\xc0-\xc7].[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "") --test(f6 /0) -> OF Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^\x66\x38\x0f][\xf7][\x00-\x07\x40-\x47\x80-\x87\xc0-\xc7]....[\x74\x75\x78\x79\x7a\x7b\x7f]", "") --test(f7 /0) -> Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^\x66\x38\x0f][\xf7][\x00-\x07\x40-\x47\x80-\x87\xc0-\xc7]....[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "") --test(f7 /0) -> OF Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[66][\xf7][\x00-\x07\x40-\x47\x80-\x87\xc0-\xc7]..[\x74\x75\x78\x79\x7a\x7b\x7f]", "") --test(66 f7 /0) -> Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[66][\xf7][\x00-\x07\x40-\x47\x80-\x87\xc0-\xc7]..[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "") --test (66 f7 /0) -> OF Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^0f][\x84].[\x74\x75\x78\x79\x7a\x7b\x7f]", "") --Test(84) -> Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^0f][\x84].[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "") --Test(84) -> OF Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^0f][\x85].[\x74\x75\x78\x79\x7a\x7b\x7f]", "") --Test(85) -> Jcc
tests = tests + count
_, count = string.gsub(temp_hex_data, "[^0f][\x85].[\x0f][\x84\x85\x88\x89\x8a\x8b\x8f]", "") --Test(85) -> OF Jcc
tests = tests + count

if opts["v"] == true then print("TEST -> Jcc: " .. tests) end

--a8 XX
--a9 XX XX XX XX
--66 a9 XX XX
--f6 XX XX
--f7 XX XX XX XX XX
--66 f6 XX XX XX
--84 XX
--85 XX

_, count = string.gsub(temp_hex_data, "[^\x0f][\x70-\x7F]", "")
local cmpjccs = count
_, count = string.gsub(temp_hex_data, "[\x0f][\x80-\x8f]", "")
cmpjccs = cmpjccs + count
if opts["v"] == true then print("Jcc's (that would have preceding CMP): " .. cmpjccs) end
--TEST -> Jcc
_, count = string.gsub(temp_hex_data, "[^38][\x3c].[\x70-\x7F]", "") --Cmp(3c) -> Jcc
local cmps = count
_, count = string.gsub(temp_hex_data, "[^38][\x3c].[\x0f][\x80-\x8f]", "") --Cmp(3c) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x66\x38][\x3d]....[\x70-\x7F]", "") --Cmp(3d) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x66\x38][\x3d]....[\x0f][\x80-\x8f]", "") --Cmp(3d) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[66][\x3d]..[\x70-\x7F]", "") --Cmp(66 3d) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[66][\x3d]..[\x0f][\x80-\x8f]", "") --Cmp (66 3d) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f][\x80][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff].[\x70-\x7F]", "") --Cmp(80 /7) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f][\x80][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff].[\x0f][\x80-\x8f]", "") --Cmp(80 /7) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x66\x0f][\x81][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff]....[\x70-\x7F]", "") --Cmp(81 /7) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x66\x0f][\x81][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff]....[\x0f][\x80-\x8f]", "") --Cmp(81 /7) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[66][\x81][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff]..[\x70-\x7F]", "") --Cmp(66 81 /7) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[66][\x81][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff]..[\x0f][\x80-\x8f]", "") --Cmp (66 81 /7) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f][\x83][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff].[\x70-\x7F]", "") --Cmp(83 /7) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f][\x83][\x38-\x3f\x78-\x7f\xb8-\xbf\xf8-\xff].[\x0f][\x80-\x8f]", "") --Cmp(83 /7) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x00-\x03\x06-\x0b\x0e\x0f\x10-\x13\x16-\x1b\x1e\x1f\x20-\x23\x26-\x2b\x2e\x2f\x30-\x33\x36-\x3b\x3e\x3f\xc0-\xff][\x70-\x7F]", "") --Cmp(38) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x00-\x03\x06-\x0b\x0e\x0f\x10-\x13\x16-\x1b\x1e\x1f\x20-\x23\x26-\x2b\x2e\x2f\x30-\x33\x36-\x3b\x3e\x3f\xc0-\xff][\x0f][\x80-\x8f]", "") --Cmp(38) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x40-\x43\x45-\x4b\x4d-\x4f\x50-\x53\x55-\x5b\x5d-\x5f\x60-\x63\x65-\x6b\x6d-\x6f\x70-\x73\x75-\x7b\x7d-\x7f].[\x70-\x7F]", "") --Cmp(38/1) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x40-\x43\x45-\x4b\x4d-\x4f\x50-\x53\x55-\x5b\x5d-\x5f\x60-\x63\x65-\x6b\x6d-\x6f\x70-\x73\x75-\x7b\x7d-\x7f].[\x0f][\x80-\x8f]", "") --Cmp(38/1) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x80-\x83\x85-\x8b\x8d-\x8f\x90-\x93\x95-\x9b\x9d-\x9f\xa0-\xa3\xa5-\xab\xad-\xaf\xb0-\xb3\xb5-\xbb\xbd-\xbf]....[\x70-\x7F]", "") --Cmp(38/4) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x80-\x83\x85-\x8b\x8d-\x8f\x90-\x93\x95-\x9b\x9d-\x9f\xa0-\xa3\xa5-\xab\xad-\xaf\xb0-\xb3\xb5-\xbb\xbd-\xbf]....[\x0f][\x80-\x8f]", "") --Cmp(38/4) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x44\x4c\x54\x5c\x64\x6c\x74\x7c]..[\x70-\x7F]", "") --Cmp(38/2) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x44\x4c\x54\x5c\x64\x6c\x74\x7c]..[\x0f][\x80-\x8f]", "") --Cmp(38/2) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].....[\x70-\x7F]", "") --Cmp(38/5) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x38][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].....[\x0f][\x80-\x8f]", "") --Cmp(38/5) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x00-\x03\x06-\x0b\x0e\x0f\x10-\x13\x16-\x1b\x1e\x1f\x20-\x23\x26-\x2b\x2e\x2f\x30-\x33\x36-\x3b\x3e\x3f\xc0-\xff][\x70-\x7F]", "") --Cmp(39) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x00-\x03\x06-\x0b\x0e\x0f\x10-\x13\x16-\x1b\x1e\x1f\x20-\x23\x26-\x2b\x2e\x2f\x30-\x33\x36-\x3b\x3e\x3f\xc0-\xff][\x0f][\x80-\x8f]", "") --Cmp(39) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x40-\x43\x45-\x4b\x4d-\x4f\x50-\x53\x55-\x5b\x5d-\x5f\x60-\x63\x65-\x6b\x6d-\x6f\x70-\x73\x75-\x7b\x7d-\x7f].[\x70-\x7F]", "") --Cmp(39/1) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x40-\x43\x45-\x4b\x4d-\x4f\x50-\x53\x55-\x5b\x5d-\x5f\x60-\x63\x65-\x6b\x6d-\x6f\x70-\x73\x75-\x7b\x7d-\x7f].[\x0f][\x80-\x8f]", "") --Cmp(39/1) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x80-\x83\x85-\x8b\x8d-\x8f\x90-\x93\x95-\x9b\x9d-\x9f\xa0-\xa3\xa5-\xab\xad-\xaf\xb0-\xb3\xb5-\xbb\xbd-\xbf]....[\x70-\x7F]", "") --Cmp(39/4) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x80-\x83\x85-\x8b\x8d-\x8f\x90-\x93\x95-\x9b\x9d-\x9f\xa0-\xa3\xa5-\xab\xad-\xaf\xb0-\xb3\xb5-\xbb\xbd-\xbf]....[\x0f][\x80-\x8f]", "") --Cmp(39/4) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x44\x4c\x54\x5c\x64\x6c\x74\x7c]..[\x70-\x7F]", "") --Cmp(39/2) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x44\x4c\x54\x5c\x64\x6c\x74\x7c]..[\x0f][\x80-\x8f]", "") --Cmp(39/2) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].....[\x70-\x7F]", "") --Cmp(39/5) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x39][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].....[\x0f][\x80-\x8f]", "") --Cmp(39/5) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x00-\x03\x06-\x0b\x0e\x0f\x10-\x13\x16-\x1b\x1e\x1f\x20-\x23\x26-\x2b\x2e\x2f\x30-\x33\x36-\x3b\x3e\x3f\xc0-\xff][\x70-\x7F]", "") --Cmp(3a) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x00-\x03\x06-\x0b\x0e\x0f\x10-\x13\x16-\x1b\x1e\x1f\x20-\x23\x26-\x2b\x2e\x2f\x30-\x33\x36-\x3b\x3e\x3f\xc0-\xff][\x0f][\x80-\x8f]", "") --Cmp(3a) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x40-\x43\x45-\x4b\x4d-\x4f\x50-\x53\x55-\x5b\x5d-\x5f\x60-\x63\x65-\x6b\x6d-\x6f\x70-\x73\x75-\x7b\x7d-\x7f].[\x70-\x7F]", "") --Cmp(3a/1) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x40-\x43\x45-\x4b\x4d-\x4f\x50-\x53\x55-\x5b\x5d-\x5f\x60-\x63\x65-\x6b\x6d-\x6f\x70-\x73\x75-\x7b\x7d-\x7f].[\x0f][\x80-\x8f]", "") --Cmp(3a/1) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x80-\x83\x85-\x8b\x8d-\x8f\x90-\x93\x95-\x9b\x9d-\x9f\xa0-\xa3\xa5-\xab\xad-\xaf\xb0-\xb3\xb5-\xbb\xbd-\xbf]....[\x70-\x7F]", "") --Cmp(3a/4) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x80-\x83\x85-\x8b\x8d-\x8f\x90-\x93\x95-\x9b\x9d-\x9f\xa0-\xa3\xa5-\xab\xad-\xaf\xb0-\xb3\xb5-\xbb\xbd-\xbf]....[\x0f][\x80-\x8f]", "") --Cmp(3a/4) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x44\x4c\x54\x5c\x64\x6c\x74\x7c]..[\x70-\x7F]", "") --Cmp(3a/2) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x44\x4c\x54\x5c\x64\x6c\x74\x7c]..[\x0f][\x80-\x8f]", "") --Cmp(3a/2) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].....[\x70-\x7F]", "") --Cmp(3a/5) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x3a][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].....[\x0f][\x80-\x8f]", "") --Cmp(3a/5) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x00-\x03\x06-\x0b\x0e\x0f\x10-\x13\x16-\x1b\x1e\x1f\x20-\x23\x26-\x2b\x2e\x2f\x30-\x33\x36-\x3b\x3e\x3f\xc0-\xff][\x70-\x7F]", "") --Cmp(3b) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x00-\x03\x06-\x0b\x0e\x0f\x10-\x13\x16-\x1b\x1e\x1f\x20-\x23\x26-\x2b\x2e\x2f\x30-\x33\x36-\x3b\x3e\x3f\xc0-\xff][\x0f][\x80-\x8f]", "") --Cmp(3b) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x40-\x43\x45-\x4b\x4d-\x4f\x50-\x53\x55-\x5b\x5d-\x5f\x60-\x63\x65-\x6b\x6d-\x6f\x70-\x73\x75-\x7b\x7d-\x7f].[\x70-\x7F]", "") --Cmp(3b/1) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x40-\x43\x45-\x4b\x4d-\x4f\x50-\x53\x55-\x5b\x5d-\x5f\x60-\x63\x65-\x6b\x6d-\x6f\x70-\x73\x75-\x7b\x7d-\x7f].[\x0f][\x80-\x8f]", "") --Cmp(3b/1) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x80-\x83\x85-\x8b\x8d-\x8f\x90-\x93\x95-\x9b\x9d-\x9f\xa0-\xa3\xa5-\xab\xad-\xaf\xb0-\xb3\xb5-\xbb\xbd-\xbf]....[\x70-\x7F]", "") --Cmp(3b/4) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x80-\x83\x85-\x8b\x8d-\x8f\x90-\x93\x95-\x9b\x9d-\x9f\xa0-\xa3\xa5-\xab\xad-\xaf\xb0-\xb3\xb5-\xbb\xbd-\xbf]....[\x0f][\x80-\x8f]", "") --Cmp(3b/4) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x44\x4c\x54\x5c\x64\x6c\x74\x7c]..[\x70-\x7F]", "") --Cmp(3b/2) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x44\x4c\x54\x5c\x64\x6c\x74\x7c]..[\x0f][\x80-\x8f]", "") --Cmp(3b/2) -> OF Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].....[\x70-\x7F]", "") --Cmp(3b/5) -> Jcc
cmps = cmps + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].....[\x0f][\x80-\x8f]", "") --Cmp(3b/5) -> OF Jcc
cmps = cmps + count

if opts["v"] == true then print("CMP -> Jcc: " .. cmps) end

--Getting Ratios
local test_p = (tests / testjccs) * 100
local cmp_p = (cmps / cmpjccs) * 100
local conditional_p = ((cmps + tests) / cmpjccs) * 100
if opts["r"] == true then print("Test->Jump Ratio: " .. test_p) end
if opts["r"] == true then print("Cmp->Jump Ratio: " .. cmp_p) end
if opts["r"] == true then print("Overall Check->Jump Ratio: " .. conditional_p) end

--local test_t = 8 --lower is not code, higher is code
--local cmp_t = 5 --lower is not code, higher is code
--local check_t = 8 --lower is not code, higher is code


--Confidence checking
if ((test_p > 5) and (test_p < 10)) then
	fverdict = fverdict + 1
	if opts["d"] == true then print ("Test->Jump: probably code") end
elseif ((test_p > 10) and (test_p < 15)) then
	fverdict = fverdict + 2
	if opts["d"] == true then print ("Test->Jump: likely code") end
elseif (test_p > 15) then
	fverdict = fverdict + 3
	if opts["d"] == true then print ("Test->Jump: very likely code") end	
else 
	fverdict = fverdict - 1
	if opts["d"] == true then print ("Test->Jump: unlikely to be code") end
end

--Confidence checking
if ((cmp_p > 5) and (cmp_p < 10)) then
	fverdict = fverdict + .5
	if opts["d"] == true then print ("Cmp->Jump: maybe code") end
elseif ((cmp_p > 10) and (cmp_p < 15)) then
	fverdict = fverdict + .8
	if opts["d"] == true then print ("Cmp->Jump: likely code") end
else
	if opts["d"] == true then print ("Cmp->Jump: unsure") end
end

--Confidence checking
if (conditional_p > 10) then
	fverdict = fverdict + 1
	if opts["d"] == true then print ("Check->Jump: likely code") end
elseif (conditional_p < 5) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("Check->Jump: unlikely code") end	
else 						
	if opts["d"] == true then print ("Check->Jump: unsure") end
end

--egrep ':\s+(4. |66 )?81.+?\scmp\s' all.dump
--3c XX
--3d XX XX XX XX
--66 3d XX XX
--80 XX XX
--81 XX XX XX XX XX
--66 81 XX XX XX
--83 XX XX
--38 XX (but not below forms)
--38 04/0c/14/1c/24/2c/34/3c/40-43/45-4b/4d-4f/50-53/55-5b/5d-5f/60-63/65-6b/6d-6f/70-73/75-7b/7d-7f XX
--38 05/0d/15/1d/25/2d/35/3d/80-83/85-8b/8d-8f/90-93/95-9b/9d-9f/a0-a3/a5-ab/ad-af/b0-b3/b5-bb/bd-bf XX XX XX XX
--38 44/4c/54/5c/64/6c/74/7c XX XX
--38 84/8c/94/9c/a4/ac/b4/bc XX XX XX XX XX
--39 XX (but not below forms)
--39 04/0c/14/1c/24/2c/34/3c/40-43/45-4b/4d-4f/50-53/55-5b/5d-5f/60-63/65-6b/6d-6f/70-73/75-7b/7d-7f XX
--39 05/0d/15/1d/25/2d/35/3d/80-83/85-8b/8d-8f/90-93/95-9b/9d-9f/a0-a3/a5-ab/ad-af/b0-b3/b5-bb/bd-bf XX XX XX XX
--39 44/4c/54/5c/64/6c/74/7c XX XX
--39 84/8c/94/9c/a4/ac/b4/bc XX XX XX XX XX
--3a XX (but not below forms)
--3a 04/0c/14/1c/24/2c/34/3c/40-43/45-4b/4d-4f/50-53/55-5b/5d-5f/60-63/65-6b/6d-6f/70-73/75-7b/7d-7f XX
--3a 05/0d/15/1d/25/2d/35/3d/80-83/85-8b/8d-8f/90-93/95-9b/9d-9f/a0-a3/a5-ab/ad-af/b0-b3/b5-bb/bd-bf XX XX XX XX
--3a 44/4c/54/5c/64/6c/74/7c XX XX
--3a 84/8c/94/9c/a4/ac/b4/bc XX XX XX XX XX
--3b XX (but not below forms) (we likely wont see this form, 39 is typically chosen for CMP reg, reg, not an equally valid 3b)
--3b 04/0c/14/1c/24/2c/34/3c/40-43/45-4b/4d-4f/50-53/55-5b/5d-5f/60-63/65-6b/6d-6f/70-73/75-7b/7d-7f XX
--3b 05/0d/15/1d/25/2d/35/3d/80-83/85-8b/8d-8f/90-93/95-9b/9d-9f/a0-a3/a5-ab/ad-af/b0-b3/b5-bb/bd-bf XX XX XX XX
--3b 44/4c/54/5c/64/6c/74/7c XX XX
--3b 84/8c/94/9c/a4/ac/b4/bc XX XX XX XX XX

--------------------------------------------------------------------------------------
--					Unlikely Machne Code											--
--------------------------------------------------------------------------------------
if opts["v"] == true then print("\n\nUnlikely Fencing: ") end
_, count = string.gsub(temp_hex_data, "[^\x38\x3A][\x0f][\xae][\xe9-\xef\xf1-\xf7\xf9-\xff]", "") --LFence/MFence/SFence
local fences = count
if opts["v"] == true then print("Unlikely Fences " .. fences) end
local fences_r = length / fences
if opts["r"] == true then print("Unlikely Fences Metric: " .. fences_r) end

--Confidence checking
if (fences_r < 5000000) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("Fences: unlikely code") end	
else
	if opts["d"] == true then print ("Fences: unsure") end
end
--note that this could also be a valid SCABS op preceded from \x0f data as operand from previous op
--there are plenty of dumb luck reasons that this could show up.


--Unlikely ModR/M (Op R/R) instructions
if opts["v"] == true then print("\n\nUnlikely ModR/M Combos: ") end
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x32][\xc0-ff]", "") --XOR r8/r8
if opts["v"] == true then print("XOR r8/r8: " .. count) end
if opts["r"] == true then print("XOR r8/r8 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .0001) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("XOR r8/r8: unlikely code") end	
else
	if opts["d"] == true then print ("XOR r8/r8: unsure") end
end
local modrms = count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x33][\xc0-ff]", "") --XOR r32/r32
if opts["v"] == true then print("XOR r32/r32: " .. count) end
if opts["r"] == true then print("XOR r32/r32 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .003) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("XOR r32/r32: unlikely code") end	
else
	if opts["d"] == true then print ("XOR r32/r32: unsure") end
end
modrms = modrms + count

--Not using this data in decision making; theory ~= practice
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x02][\xc0-ff]", "") --ADD r8/r8
if opts["v"] == true then print("ADD r8/r8: " .. count) end
if opts["r"] == true then print("ADD r8/r8 ratio: " .. count / length) end
modrms = modrms + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x03][\xc0-ff]", "") --ADD r32/r32
if opts["v"] == true then print("ADD r32/r32: " .. count) end
if opts["r"] == true then print("ADD r32/r32 ratio: " .. count / length) end
modrms = modrms + count

_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x22][\xc0-ff]", "") --AND r8/r8
if opts["v"] == true then print("AND r8/r8: " .. count) end
if opts["r"] == true then print("AND r8/r8 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .000085) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("AND r8/r8: unlikely code") end	
else
	if opts["d"] == true then print ("AND r8/r8: unsure") end
end
modrms = modrms + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x23][\xc0-ff]", "") --AND r32/r32
if opts["v"] == true then print("AND r32/r32: " .. count) end
if opts["r"] == true then print("AND r32/r32 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .000025) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("AND r32/r32: unlikely code") end	
else
	if opts["d"] == true then print ("AND r32/r32: unsure") end
end
modrms = modrms + count

_, count = string.gsub(temp_hex_data, "[^\x0f][\x3a][\xc0-ff]", "") --CMP r8/r8
if opts["v"] == true then print("CMP r8/r8: " .. count) end
if opts["r"] == true then print("CMP r8/r8 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .000058) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("CMP r8/r8: unlikely code") end	
else
	if opts["d"] == true then print ("CMP r8/r8: unsure") end
end
modrms = modrms + count
_, count = string.gsub(temp_hex_data, "[^\x38][\x3b][\xc0-ff]", "") --CMP r32/r32
if opts["v"] == true then print("CMP r32/r32: " .. count) end
if opts["r"] == true then print("CMP r32/r32 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .00005) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("CMP r32/r32: unlikely code") end	
else
	if opts["d"] == true then print ("CMP r32/r32: unsure") end
end
modrms = modrms + count

_, count = string.gsub(temp_hex_data, "[^\x0f][\x8a][\xc0-ff]", "") --MOV r8/r8
if opts["v"] == true then print("MOV r8/r8: " .. count) end
if opts["r"] == true then print("MOV r8/r8 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .000022) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("MOV r8/r8: unlikely code") end	
else
	if opts["d"] == true then print ("MOV r8/r8: unsure") end
end
modrms = modrms + count
_, count = string.gsub(temp_hex_data, "[^\x0f][\x8b][\xc0-ff]", "") --MOV r32/r32
if opts["v"] == true then print("MOV r32/r32: " .. count) end
if opts["r"] == true then print("MOV r32/r32 ratio: " .. count / length) end
--Not using this data in decision making; theory ~= practice
modrms = modrms + count

_, count = string.gsub(temp_hex_data, "[^\x38\x3a][\x0a][\xc0-ff]", "") --OR r8/r8
if opts["v"] == true then print("OR r8/r8: " .. count) end
if opts["r"] == true then print("OR r8/r8 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .0002) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("OR r8/r8: unlikely code") end	
else
	if opts["d"] == true then print ("OR r8/r8: unsure") end
end
modrms = modrms + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38\x3A][\x0b][\xc0-ff]", "") --OR r32/r32
if opts["v"] == true then print("OR r32/r32: " .. count) end
if opts["r"] == true then print("OR r32/r32 ratio: " .. count / length) end
--Not using this data in decision making; theory ~= practice
modrms = modrms + count

_, count = string.gsub(temp_hex_data, "[^\x38\x0f][\x2a][\xc0-ff]", "") --SUB r8/r8
if opts["v"] == true then print("SUB r8/r8: " .. count) end
if opts["r"] == true then print("SUB r8/r8 ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .0001) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("SUB r8/r8: unlikely code") end	
else
	if opts["d"] == true then print ("SUB r8/r8: unsure") end
end
modrms = modrms + count
_, count = string.gsub(temp_hex_data, "[^\x0f\x38][\x2b][\xc0-ff]", "") --SUB r32/r32
if opts["v"] == true then print("SUB r32/r32: " .. count) end
if opts["r"] == true then print("SUB r32/r32 ratio: " .. count / length) end
--Not using this data in decision making; theory ~= practice
modrms = modrms + count

if opts["v"] == true then print("Total Unlikely ModR/M Combos: " .. modrms) end
--Getting Ratios
modrms_r = (modrms / length) * 100
--Not using this data in decision making due to granual metric usage above
if opts["r"] == true then print("Unlikely ModR/M Metric: " .. modrms_r) end

--Unlikely SIB instructions
if opts["v"] == true then print("\n\nUnlikely SIB instructions: ") end
_, count = string.gsub(temp_hex_data, "[^\x40-4f\x0f\x38][\x30-\x33][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x44\x4c\x54\x5c\x64\x6c\x74\x7c\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x60-\x67\xa0-\xa7\xe0-\xe7]", "") --XOR
if opts["v"] == true then print("XOR 'none' SIB " .. count) end
if opts["r"] == true then print("XOR SIB ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .001) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("XOR SIB: unlikely code") end	
else
	if opts["d"] == true then print ("XOR SIB: unsure") end
end
local sibs = count

_, count = string.gsub(temp_hex_data, "[^\x40-4f\x0f\x38\x3a][\x00-\x03][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x44\x4c\x54\x5c\x64\x6c\x74\x7c\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x60-\x67\xa0-\xa7\xe0-\xe7]", "") --ADD
if opts["v"] == true then print("ADD 'none' SIB " .. count) end
if opts["r"] == true then print("ADD SIB ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .002) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("ADD SIB: unlikely code") end	
else
	if opts["d"] == true then print ("ADD SIB: unsure") end
end
sibs = sibs + count

_, count = string.gsub(temp_hex_data, "[^\x40-4f\x0f\x38\x3a][\x20-\x23][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x44\x4c\x54\x5c\x64\x6c\x74\x7c\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x60-\x67\xa0-\xa7\xe0-\xe7]", "") --AND
if opts["v"] == true then print("AND 'none' SIB " .. count) end
if opts["r"] == true then print("AND SIB ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .002) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("AND SIB: unlikely code") end	
else
	if opts["d"] == true then print ("AND SIB: unsure") end
end
sibs = sibs + count

_, count = string.gsub(temp_hex_data, "[^\x40-4f\x0f\x38\x3a][\x38-\x3b][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x44\x4c\x54\x5c\x64\x6c\x74\x7c\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x60-\x67\xa0-\xa7\xe0-\xe7]", "") --CMP
if opts["v"] == true then print("CMP 'none' SIB " .. count) end
if opts["r"] == true then print("CMP SIB ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .0005) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("CMP SIB: unlikely code") end	
else
	if opts["d"] == true then print ("CMP SIB: unsure") end
end
sibs = sibs + count

_, count = string.gsub(temp_hex_data, "[^\x40-4f\x0f][\x88-\x8b][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x44\x4c\x54\x5c\x64\x6c\x74\x7c\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x60-\x67\xa0-\xa7\xe0-\xe7]", "") --MOV
if opts["v"] == true then print("MOV 'none' SIB " .. count) end
if opts["r"] == true then print("MOV SIB ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .0003) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("MOV SIB: unlikely code") end	
else
	if opts["d"] == true then print ("MOV SIB: unsure") end
end
sibs = sibs + count

_, count = string.gsub(temp_hex_data, "[^\x40-4f\x0f\x38\x3a][\x08-\x0b][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x44\x4c\x54\x5c\x64\x6c\x74\x7c\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x60-\x67\xa0-\xa7\xe0-\xe7]", "") --OR
if opts["v"] == true then print("OR 'none' SIB " .. count) end
if opts["r"] == true then print("OR SIB ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .0002) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("OR SIB: unlikely code") end	
else
	if opts["d"] == true then print ("OR SIB: unsure") end
end
sibs = sibs + count

_, count = string.gsub(temp_hex_data, "[^\x40-4f\x0f\x38][\x28-\x2b][\x04\x0c\x14\x1c\x24\x2c\x34\x3c\x44\x4c\x54\x5c\x64\x6c\x74\x7c\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x60-\x67\xa0-\xa7\xe0-\xe7]", "") --SUB
if opts["v"] == true then print("SUB 'none' SIB " .. count) end
if opts["r"] == true then print("SUB SIB ratio: " .. count / length) end
--Confidence checking
if ((count / length) > .0005) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("SUB SIB: unlikely code") end	
else
	if opts["d"] == true then print ("SUB SIB: unsure") end
end
sibs = sibs + count

if opts["v"] == true then print("Total 'none' SIBs: " .. sibs) end
--Getting Ratios
sibs_r = (sibs / length) * 100
if opts["r"] == true then print("'none' SIB Metric: " .. sibs_r) end
--Confidence checking
if ((count / length) > .25) then
	fverdict = fverdict - 1
	if opts["d"] == true then print ("SIB: unlikely code") end	
else
	if opts["d"] == true then print ("SIB: unsure") end
end

--Unlikely REX prefix implementations
--Not using this data in decision making. Although there are noticable patterns, these patterns didn't match up
--with theory. There is most likely a logical reason for why these results appear. Even though the patterns are
--consistent; I only want to use hueristics that I can explain the results of. These hueristics are left in this
--script for reporting, however.
if opts["v"] == true then print("\n\nUnlikely XOR instructions: ") end
_, count = string.gsub(temp_hex_data, "[\x40\x42\x48\x4a][\x30\x31][\xc0-\xc3\xc8-\xcb\xd0-\xd3\xd8-\xdb]", "") --XOR
if opts["v"] == true then print("Unlikely REX XOR " .. count) end
if opts["r"] == true then print("Unlikely REX XOR ratio: " .. count / length) end
local rexes = count

_, count = string.gsub(temp_hex_data, "[\x40\x42\x48\x4a][\x00\x01][\xc0-\xc3\xc8-\xcb\xd0-\xd3\xd8-\xdb]", "") --XOR
if opts["v"] == true then print("Unlikely REX ADD " .. count) end
if opts["r"] == true then print("Unlikely REX ADD ratio: " .. count / length) end
rexes = count

_, count = string.gsub(temp_hex_data, "[\x40\x42\x48\x4a][\x20\x21][\xc0-\xc3\xc8-\xcb\xd0-\xd3\xd8-\xdb]", "") --XOR
if opts["v"] == true then print("Unlikely REX AND " .. count) end
if opts["r"] == true then print("Unlikely REX AND ratio: " .. count / length) end
rexes = count

_, count = string.gsub(temp_hex_data, "[\x40\x42\x48\x4a][\x38\x39][\xc0-\xc3\xc8-\xcb\xd0-\xd3\xd8-\xdb]", "") --XOR
if opts["v"] == true then print("Unlikely REX CMP " .. count) end
if opts["r"] == true then print("Unlikely REX CMP ratio: " .. count / length) end
rexes = count

_, count = string.gsub(temp_hex_data, "[\x40\x42\x48\x4a][\x88\x89][\xc0-\xc3\xc8-\xcb\xd0-\xd3\xd8-\xdb]", "") --XOR
if opts["v"] == true then print("Unlikely REX MOV " .. count) end
if opts["r"] == true then print("Unlikely REX MOV ratio: " .. count / length) end
rexes = count

_, count = string.gsub(temp_hex_data, "[\x40\x42\x48\x4a][\x08\x09][\xc0-\xc3\xc8-\xcb\xd0-\xd3\xd8-\xdb]", "") --XOR
if opts["v"] == true then print("Unlikely REX OR " .. count) end
if opts["r"] == true then print("Unlikely REX OR ratio: " .. count / length) end
rexes = count

_, count = string.gsub(temp_hex_data, "[\x40\x42\x48\x4a][\x28\x29][\xc0-\xc3\xc8-\xcb\xd0-\xd3\xd8-\xdb]", "") --XOR
if opts["v"] == true then print("Unlikely REX SUB " .. count) end
if opts["r"] == true then print("Unlikely REX SUB ratio: " .. count / length) end
rexes = count

if opts["v"] == true then print("Total Unlikely REXes: " .. rexes) end
--Getting Ratios
rexes_r = (rexes / length) * 100
if opts["r"] == true then print("Unlikely REX Metric: " .. rexes_r) end

--Print Final Verdict
--Each range of output difference are based on standard deviation ranges. 500 sample files were used to get this
--data; half were x86/64 programs and the other half were various files (non-x86/64).
fverdict = fverdict - 1.5 --normalization

if (fverdict > 9.16) then
	print ("Final Verdict: Very Likely Code (" .. fverdict .. ")")
elseif ((fverdict > 7.33) and (fverdict <= 9.16)) then
	print("Final Verdict: Likely Code (" .. fverdict .. ")")
elseif ((fverdict > 5.5) and (fverdict <= 7.33)) then
	print("Final Verdict: Probably Code (" .. fverdict .. ")")
elseif ((fverdict > 3.7) and (fverdict <= 5.5)) then
	print("Final Verdict: Maybe Code (" .. fverdict .. ")")
elseif ((fverdict > 0) and (fverdict <= 3.7)) then
	print("Final Verdict: Unsure, Code? (" .. fverdict .. ")")
elseif ((fverdict > -1.27) and (fverdict <= 0)) then
	print("Final Verdict: Maybe NonCode (" .. fverdict .. ")")
elseif ((fverdict > -3.61) and (fverdict <= -1.27)) then
	print("Final Verdict: Probably NonCode (" .. fverdict .. ")")
elseif ((fverdict > -5.94) and (fverdict <= 3.61)) then
	print("Final Verdict: Likely NonCode (" .. fverdict .. ")")
else
	print ("Final Verdict: Very Likely NonCode (" .. fverdict .. ")")
end

--]]

--Documentation of Hueristics
--[[
xor reg, reg (DONE):
	Compilers typically xor a register with itself to set the register to 0.
	Prefixes asside, this translates to a 2 byte instruction, instead, for
	example, a 5 byte mov eax, 0.

Some one-byte histogram stuff (DONE):
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

condition_test -> conditional_jmp (DONE):
	This is pretty obvious; if the code is going to do a conditional jump,
	it would make sense for there to be a conditional test preceding it.
	This is the highest fidelity hueristic.

Unlikely Operations:
	There is redundancy in machine code (30 c0 and 32 c0 are both xor al,al).
	A compiler must choose one, meaning we should never see the other. I'm
	not certain whether the above xor example is compiler specific though,
	so I will stick with "Intel Manual" suggested unlikely redundancies,
	like the fence redundancy. The idea for this hueristic is you should see
	a low amount of this metric compared to other random data. A low amount
	doesn't prove it's code, but a high amount is strong indicator it's not
--]]
