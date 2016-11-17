#include "HookUtility.h"
#include "Logger.h"
#include "wdbgexts.h"
#include "basetsd.h"

namespace md
{

	HookUtility HookUtility::s_instance;

	HookUtility::HookUtility(void)
		: m_baseAddr(0x10000000)
		, m_addrParse(0)
		, m_addrGetMethodName(0)
		, m_addrResolveMethodInfo(0)
		, m_addrVerifyJIT(0)
		, m_addrSetJIT(0)
		, m_addrUnused(0)
        , m_addrAnalyzeEmbedded(0)
		, m_addrAcroMalloc(0)
		, m_addrAcroMcp1(0)
		, m_addrAcroMcp2(0)
		, m_sigMatched(false)
	{
	}

	HookUtility::~HookUtility(void)
	{
	}

	HookUtility* HookUtility::getInstance()
	{
		return &s_instance;
	}

	void HookUtility::setBaseAddress(ULONG64 addr)
	{
		m_baseAddr = addr;
		if (searchFPSignature()) {
			LOG_TRACE("Find signature!");
		}
	}

	bool HookUtility::updateAddrUnused()
	{
		return searchUnused();
	}

	bool HookUtility::searchFPSignature()
	{
		if (!searchParse()) {
			return false;
		}
		//if (!searchVerifyJIT()) {
		//	return false;
		//}
		//if (!searchResolveMethodInfo()) {
		//	return false;
		//}
		if (!searchGetMethodName()) {
			return false;
		}
		if (!searchSetJIT()) {
			return false;
		}
        if (!searchAnalyzeEmbedded()) {
            return false;
        }
		m_sigMatched = true;
		return true;
	}

	bool HookUtility::searchRdSig()
	{
		if (!searchAcroMalloc()) {
			return false;
		}
		if (!searchAcroMcp1()) {
			return false;
		}
		if (!searchAcroMcp2()) {
			return false;
		}
		return true;
	}

	bool HookUtility::searchVerifyJIT()
	{
		//.text:106AF476 6A 00                                         push    0
		//.text:106AF478 55                                            push    ebp
		//.text:106AF479 51                                            push    ecx
		//.text:106AF47A 57                                            push    edi
		//.text:106AF47B 56                                            push    esi
		//.text:106AF47C 8B CB                                         mov     ecx, ebx
		//.text:106AF47E E8 3D 8A 02 00                                call    sub_106D7EC0 //VerifyJIT
		//.text:106AF483 5D                                            pop     ebp
		//.text:106AF484 5F                                            pop     edi
		//.text:106AF485 5E                                            pop     esi
		//.text:106AF486 5B                                            pop     ebx
		//.text:106AF487 C2 0C 00                                      retn    0Ch

		// s 0x10000000 L111e000 6A 00 55 51 57 56 8B CB E8 3D 8A 02 00

		ULONG64 searched = 0;
		char pattern[] = {0x6A,0x00,0x55,0x51,0x57,0x56,0x8B,0xCB};
		SearchMemory(m_baseAddr, 0x111e000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of VerifyJIT");
			return false;
		}
		m_addrVerifyJIT = searched + sizeof(pattern) + 5;
		return true;
	}

	bool HookUtility::searchResolveMethodInfo()
	{
		//.text:106B31E8                               loc_106B31E8:                           ; CODE XREF: sub_106B31B0+17j
		//.text:106B31E8 8B 56 14                                      mov     edx, [esi+14h]
		//.text:106B31EB 8B 82 88 00 00 00                             mov     eax, [edx+88h]
		//.text:106B31F1 8B 5C B8 08                                   mov     ebx, [eax+edi*4+8] // EDI is method index, EBX is method info addr
		//.text:106B31F5 85 DB                                         test    ebx, ebx
		//.text:106B31F7 75 16                                         jnz     short loc_106B320F
		//.text:106B31F9 8B 4E 10                                      mov     ecx, [esi+10h]
		//.text:106B31FC 57                                            push    edi
		//.text:106B31FD E8 DE 90 F9 FF                                call    sub_1064C2E0
		//.text:106B3202 8B 4E 08                                      mov     ecx, [esi+8]
		//.text:106B3205 68 16 04 00 00                                push    416h
		//.text:106B320A E8 11 4C FE FF                                call    throwVerifyError

		// s 0x10000000 L111e000 8B 56 14 8B 82 88 00 00 00 8B 5C B8 08

		ULONG64 searched = 0;
		char pattern[] = {0x8B,0x56,0x14,0x8B,0x82,0x88,0x00,0x00,0x00,0x8B,0x5C,0xB8,0x08};
		SearchMemory(m_baseAddr, 0x111e000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of ResolveMethodInfo");
			return false;
		}
		m_addrResolveMethodInfo = searched + sizeof(pattern);
		return true;
	}

	bool HookUtility::searchGetMethodName()
	{
		//.text:106C4750                               MethodInfo__getMethodName proc near     ; CODE XREF: sub_1064BE80+6p
		//.text:106C4750                                                                       ; sub_106C4780+2p
		//.text:106C4750 8B 41 10                                      mov     eax, [ecx+10h]
		//.text:106C4753 A8 01                                         test    al, 1
		//.text:106C4755 74 13                                         jz      short loc_106C476A
		//.text:106C4757 83 E0 FE                                      and     eax, 0FFFFFFFEh
		//.text:106C475A 74 0C                                         jz      short loc_106C4768
		//.text:106C475C 8B 40 0C                                      mov     eax, [eax+0Ch]
		//.text:106C475F 52                                            push    edx
		//.text:106C4760 8B D0                                         mov     edx, eax
		//.text:106C4762 E8 B9 F7 FF FF                                call    MethodInfo__getMethodNameWithTraits
		//.text:106C4767 C3                                            retn

		// s 0x10000000 L111e000 8B 41 10 A8 01 74 13 83 E0 FE 74 0C
		ULONG64 searched = 0;
		char pattern[] = {0x8B,0x41,0x10,0xA8,0x01,0x74,0x13,0x83,0xE0,0xFE,0x74,0x0C};
		SearchMemory(m_baseAddr, 0x111e000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of GetMethodName");
			return false;
		}
		m_addrGetMethodName = searched;
		return true;
	}

	bool HookUtility::searchParse()
	{
		//.text:106B5670                               AbcParser__parse proc near              ; CODE XREF: AbcParser__decodeAbc+8Dp
		//.text:106B5670
		//.text:106B5670                               arg_0           = dword ptr  4
		//.text:106B5670
		//.text:106B5670 56                                            push    esi
		//.text:106B5671 8B F1                                         mov     esi, ecx
		//.text:106B5673 8B 46 10                                      mov     eax, [esi+10h]
		//.text:106B5676 8B 88 D0 00 00 00                             mov     ecx, [eax+0D0h]
		//.text:106B567C E8 9F D3 FF FF                                call    sub_106B2A20
		//.text:106B5681 8B 4E 10                                      mov     ecx, [esi+10h]
		//.text:106B5684 8B 89 D4 00 00 00                             mov     ecx, [ecx+0D4h]
		//.text:106B568A E8 91 D3 FF FF                                call    sub_106B2A20
		
		// s 0x10000000 L111e000 56 8B F1 8B 46 10 8B 88 D0 00 00 00

		ULONG64 searched = 0;
		char pattern[] = {0x56,0x8B,0xF1,0x8B,0x46,0x10,0x8B,0x88,0xD0,0x00,0x00,0x00};
		SearchMemory(m_baseAddr, 0x111e000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of Parse");
			return false;
		}
		m_addrParse = searched;
		return true;
	}

	bool HookUtility::searchSetJIT()
	{
		//.text:106D7E80 8B 4C 24 08                                   mov     ecx, [esp+code]
		//.text:106D7E84 56                                            push    esi
		//.text:106D7E85 8B 74 24 08                                   mov     esi, [esp+4+mi]
		//.text:106D7E89 8B 46 30                                      mov     eax, [esi+30h]
		//.text:106D7E8C 25 FF FF 7F FF                                and     eax, 0FF7FFFFFh
		//.text:106D7E91 0D 00 00 20 80                                or      eax, 80200000h
		//.text:106D7E96 56                                            push    esi

		// s 0x10000000 L111e000 8B 4C 24 08 56 8B 74 24 08 8B 46 30 25 FF FF 7F FF

		ULONG64 searched = 0;
		char pattern[] = {0x8B,0x4C,0x24,0x08,0x56,0x8B,0x74,0x24,0x08,0x8B,0x46,0x30,0x25,0xFF,0xFF,0x7F,0xFF};
		SearchMemory(m_baseAddr, 0x111e000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of SetJIT");
			return false;
		}
		m_addrSetJIT = searched;
		return true;
	}

	bool HookUtility::searchUnused()
	{
		//mov ecx,esi // 0x89,0xf1
		//// offset = 106C4750 - 1000ee4a - 5 = 6B5901
		//call 0x******** // 0xE8,0x01,0x59,0x6b,0x00
		//pop  esi // 0x5E
		//pop ecx // 0x59
		//mov eax,[esi+30h] // 0x8B,0x46,0x30
		//add eax,0xFF7FFFFF // 0x25,0xFF,0xFF,0x7F,0xFF
		//// offset = 106d7e91 - 1000ee59 - 5 = 6C9033
		//jmp 0x******** // 0xE9,0x33,0x90,0x6C,0x00

		// at least 22 bytes
		// s 0x10000000 L111e000 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 

		ULONG64 searched = 0;
		char pattern[] = {0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
			0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
			0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC};
		SearchMemory(m_baseAddr, 0x111e000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of Unused");
			return false;
		}
		m_addrUnused = (searched%2 == 0) ? searched+2 : searched+1; // why +1 here? reserve "INT 3" before ourselves instructions
		return true;
	}




	bool HookUtility::searchAcroMalloc()
	{
		//.text:2380760C                  ; int __cdecl acro_malloc(int, size_t Size)
		//.text:2380760C                  acro_malloc     proc near               ; CODE XREF: acro_alloc_content+13p
		//.text:2380760C                                                          ; sub_23807AFF+12p ...
		//.text:2380760C
		//.text:2380760C                  arg_0           = dword ptr  4
		//.text:2380760C                  Size            = dword ptr  8
		//.text:2380760C
		//.text:2380760C 56                               push    esi
		//.text:2380760D 57                               push    edi
		//.text:2380760E 8B 7C 24 10                      mov     edi, [esp+8+Size]
		//.text:23807612 85 FF                            test    edi, edi
		//.text:23807614 75 01                            jnz     short loc_23807617
		//.text:23807616 47                               inc     edi
		//.text:23807617
		//.text:23807617                  loc_23807617:                           ; CODE XREF: acro_malloc+8j
		//.text:23807617 57                               push    edi             ; Size
		//.text:23807618 FF 15 7C E2 8F 23                call    ds:malloc
		//.text:2380761E 8B F0                            mov     esi, eax
		//.text:23807620 85 F6                            test    esi, esi
		//.text:23807622 59                               pop     ecx
		//.text:23807623 75 0D                            jnz     short loc_23807632
		//.text:23807625 FF 74 24 0C                      push    [esp+8+arg_0]
		//.text:23807629 E8 59 0E 05 00                   call    acro_report_oom
		//.text:2380762E 33 C0                            xor     eax, eax

		// s 23800000 L167000 56 57 8b 7c 24 10 85 ff 75 01 47 57

		ULONG64 searched = 0;
		char pattern[] = {0x56,0x57,0x8B,0x7C,0x24,0x10,0x85,0xFF,0x75,0x01,0x47,0x57};
		SearchMemory(0x23800000, 0x167000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of AcroMalloc");
			return false;
		}
		m_addrAcroMalloc = searched + 18;
		return true;
	}

	bool HookUtility::searchAcroMcp1()
	{
		//00 0012dd50 78147476 03e10020 04160040 000fff80 MSVCR80!_VEC_memzero+0xf3
		//01 0012dd80 238075df 03e10020 04160040 000fff9e MSVCR80!_VEC_memcpy+0x52
		//02 0012dda0 238211e6 020e9d90 04160040 0007ffcf EScript!PlugInMain+0x622f
		//03 0012ddc4 238bf4be 020e9d90 02c1a7c0 00000010 EScript!PlugInMain+0x1fe36
		//04 0012de04 2380d9d2 020e9d90 02c1a7c4 00000002 EScript!PlugInMain+0xbe10e
		//05 0012debc 2381d388 020e9d90 00000002 00000000 EScript!PlugInMain+0xc622
		//06 00000000 00000000 00000000 00000000 00000000 EScript!PlugInMain+0x1bfd8

		//.text:238075B5 55              push    ebp
		//.text:238075B6 8B EC           mov     ebp, esp
		//.text:238075B8 53              push    ebx
		//.text:238075B9 8B 5D 10        mov     ebx, [ebp+char_size]
		//.text:238075BC 56              push    esi
		//.text:238075BD 8D 34 1B        lea     esi, [ebx+ebx]
		//.text:238075C0 57              push    edi
		//.text:238075C1 8D 46 02        lea     eax, [esi+2]
		//.text:238075C4 50              push    eax             ; Size
		//.text:238075C5 FF 75 08        push    [ebp+arg_0]     ; int
		//.text:238075C8 E8 3F 00 00 00  call    acro_malloc
		//.text:238075CD 8B F8           mov     edi, eax
		//.text:238075CF 85 FF           test    edi, edi
		//.text:238075D1 59              pop     ecx
		//.text:238075D2 59              pop     ecx
		//.text:238075D3 74 32           jz      short loc_23807607
		//.text:238075D5 56              push    esi             ; Size
		//.text:238075D6 FF 75 0C        push    [ebp+Src]       ; Src
		//.text:238075D9 57              push    edi             ; Dst
		//.text:238075DA E8 73 D2 FF FF  call    memcpy
		//.text:238075DF FF 75 14        push    [ebp+arg_C]
		//.text:238075E2 66 83 24 3E 00  and     word ptr [esi+edi], 0

		// s 23800000 L167000 59 59 74 32 56 FF 75 0C 57

		ULONG64 searched = 0;
		char pattern[] = {0x59,0x59,0x74,0x32,0x56,0xFF,0x75,0x0C,0x57};
		SearchMemory(0x23800000, 0x167000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of AcroMcp1");
			return false;
		}
		m_addrAcroMcp1 = searched + 14;
		return true;
	}

	bool HookUtility::searchAcroMcp2()
	{
		//00 0012de5c 78147476 03fa0020 03d90020 001ffe80 MSVCR80!_VEC_memzero+0xc6
		//01 0012de8c 238229eb 03fa0020 03d90020 001ffee4 MSVCR80!_VEC_memcpy+0x52
		//02 0012debc 2381b9b3 021ee2b8 02c209b8 03d90020 EScript!PlugInMain+0x2163b
		//03 0012e01c 2380d557 00000000 00000010 3ffc3edd EScript!PlugInMain+0x1a603
		//04 0012e030 2381900d 021ee2b8 02cbe7a0 0012e070 EScript!PlugInMain+0xc1a7
		//05 0012e0b8 238581c3 00000000 03733418 02cbe770 EScript!PlugInMain+0x17c5d
		//06 0012e0e4 238587a4 021ee2b8 03733418 00000000 EScript!PlugInMain+0x56e13
		//07 0012e10c 2382cfde 021ee2b8 03733418 037c5ce0 EScript!PlugInMain+0x573f4
		//08 0012e1c4 23809f89 0223a8f0 02e3fd60 0223a8f0 EScript!PlugInMain+0x2bc2e
		//09 0012e1e4 23809e5f 0223a8d8 036ed578 23809f53 EScript!PlugInMain+0x8bd9
		//0a 0012e278 23806987 0224b0d4 6e68ff4c 00000030 EScript!PlugInMain+0x8aaf
		//0b 0012e30c 2384d9b8 03686b08 0224b0d0 02c40fc4 EScript!PlugInMain+0x55d7
		//0c 0012e358 2384f8c5 020b4810 0370def4 036edbf4 EScript!PlugInMain+0x4c608
		//0d 0012e3ec 238b9906 02a5554c 00000000 037c30b4 EScript!PlugInMain+0x4e515
		//0e 0012e484 00b3dd60 00000000 c0000000 00000005 EScript!PlugInMain+0xb8556
		//0f 0012e508 00b3de77 0215e758 c0000000 00000005 AcroRd32_940000!AX_ASRamFileSysSetLimitKB+0x5acea
		//10 0012e558 00ed1307 c0000000 00000005 0012e61c AcroRd32_940000!AX_ASRamFileSysSetLimitKB+0x5ae01
		//11 0012e590 00b40527 c0000000 00000005 00b3de26 AcroRd32_940000!PDFLTerm+0x119297

		//.text:238229D7                loc_238229D7:                           ; CODE XREF: sub_23822882+ABj
		//.text:238229D7 33 C0                          xor     eax, eax
		//.text:238229D9 E9 8D 00 00 00                 jmp     loc_23822A6B
		//.text:238229DE                ; ---------------------------------------------------------------------------
		//.text:238229DE
		//.text:238229DE                loc_238229DE:                           ; CODE XREF: sub_23822882+153j
		//.text:238229DE 8D 04 36                       lea     eax, [esi+esi]
		//.text:238229E1 50                             push    eax             ; Size
		//.text:238229E2 FF 75 10                       push    [ebp+Memory]    ; Src
		//.text:238229E5 53                             push    ebx             ; Dst
		//.text:238229E6 E8 67 1E FE FF                 call    memcpy
		//.text:238229EB 83 C4 0C                       add     esp, 0Ch
		//.text:238229EE 83 65 F8 00                    and     [ebp+var_8], 0

		// s 23800000 L?167000 8D 04 36 50 FF 75 10 53

		ULONG64 searched = 0;
		char pattern[] = {0x8D,0x04,0x36,0x50,0xFF,0x75,0x10,0x53};
		SearchMemory(0x23800000, 0x167000, sizeof(pattern), pattern, &searched);
		if (!searched) {
			LOG_ERROR("Cannot find signature of AcroMcp2");
			return false;
		}
		m_addrAcroMcp2 = searched + 13;
		return true;
	}

    bool HookUtility::searchAnalyzeEmbedded()
    {
        //.text:1012AF60 55                                            push    ebp
        //.text:1012AF61 8D 6C 24 94                                   lea     ebp, [esp-6Ch]
        //.text:1012AF65 81 EC FC 00 00 00                             sub     esp, 0FCh
        //.text:1012AF6B 53                                            push    ebx
        //.text:1012AF6C 56                                            push    esi
        //.text:1012AF6D 57                                            push    edi
        //.text:1012AF6E 8B F9                                         mov     edi, ecx
        //.text:1012AF70 C7 45 18 00 00 00 00                          mov     [ebp+6Ch+var_54], 0
        //.text:1012AF77 80 7D 7C 00                                   cmp     [ebp+6Ch+arg_8], 0
        //.text:1012AF7B 89 7D 50                                      mov     [ebp+6Ch+var_1C], edi
        //.text:1012AF7E 74 08                                         jz      short loc_1012AF88
        //.text:1012AF80 8B 4F 38                                      mov     ecx, [edi+38h]
        //.text:1012AF83 E8 C8 40 01 00                                call    sub_1013F050

        //s 10000000 L?111e000 55 8D 6C 24 94 81 EC FC 00 00 00 53 56 57 8B F9

        ULONG64 searched = 0;
        char pattern[] = {0x55,0x8D,0x6C,0x24,0x94,0x81,0xEC,0xFC,0x00,0x00,0x00,0x53,0x56,0x57,0x8B,0xF9};
        SearchMemory(m_baseAddr, 0x111e000, sizeof(pattern), pattern, &searched);
        if (!searched) {
            LOG_ERROR("Cannot find signature of AnalyzeEmbedded");
            return false;
        }
        m_addrAnalyzeEmbedded = searched;
        return true;
    }







}