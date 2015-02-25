# flashext

## Flash Debug Extensions Usage

	!help               - Get these help information
	!base <address>     - Set base address of flash player
	!tjit               - Trace JIT functions
	!bpjit <method_name> [<condition>]
	                    - Set breakpoint on JIT function by name
	!lnjit <address>    - Displays JIT symbols at or near given address
	!dump               - Get mapping of JIT function entry and name

*refer to code for detailed information*

## Example(CVE-2015-0311)
### Break at module loading of flash player add-on, and load flashext

	ModLoad: 10000000 1111e000   C:\WINDOWS\system32\Macromed\Flash\Flash32_16_0_0_257.ocx
	eax=00000000 ebx=00000000 ecx=05570000 edx=7c90e514 esi=00000000 edi=00000000
	eip=7c90e514 esp=020d874c ebp=020d8840 iopl=0         nv up ei pl zr na pe nc
	cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
	ntdll!KiFastSystemCallRet:
	7c90e514 c3              ret
	1:022> .load flashext

### According to previous address, set the base

	1:022> !base 10000000
	Set base address: 10000000

### Trace JIT

	1:022> !tjit
	Prepare to trace JIT
	1:022> g
	JIT Entry: 5c35d97, Method Name: rsvkskr
	JIT Entry: 5b947e1, Method Name: String/http://adobe.com/AS3/2006/builtin::replace
	JIT Entry: 5c35bff, Method Name: ep
	...
	JIT Entry: 5cdee55, Method Name: _a_-_---$/_a_--_--
	JIT Entry: 5cde7cd, Method Name: _a_-_---$/_a_-_--
	JIT Entry: 5cde730, Method Name: _a_-_-__
	JIT Entry: 5cde691, Method Name: _a_-_
	...
	JIT Entry: 5cdd5c0, Method Name: _a_-_-_/_a_-_--_
	JIT Entry: 5cdd22a, Method Name: _a_-_-_/_a_-__-
	JIT Entry: 5cab504, Method Name: 52142317523188123423632234$/52142315723170123423632234
	JIT Entry: 5cab1b8, Method Name: 52142317523188123423632234$/52142314823161123423632234
	...
	JIT Entry: 5ca0631, Method Name: 52142317523188123423632234$/for
	JIT Entry: 5c9ff10, Method Name: 52142317523188123423632234$/52142318623199123423632234
	JIT Entry: 5c9f664, Method Name: catch for/include set
	JIT Entry: 5b93677, Method Name: flash.utils::ByteArray/compress
	JIT Entry: 5c9e3c2, Method Name: catch for/52142316923182123423632234
	...
	JIT Entry: 6a1bf45, Method Name: 52142317523188123423632234$/true
	JIT Entry: 6a1916e, Method Name: catch for/const for
	JIT Entry: 6a18fce, Method Name: catch for/52142316823181123423632234
	JIT Entry: 6a18d84, Method Name: catch for/521423742387123423632234

*Note: Due to JITed characters, the entry address could be changed next time.*

### Set breakpoint at JITed entry

	!bpjit "catch for/include set"

### Display symbol by address

	1:022> !lnjit 0x6a97145
	parameter: 6a97145
	Find Near Method, address: 6a97010+0x135, method name: catch for/52142316823181123423632234

