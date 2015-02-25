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
		if (searchSignature()) {
			LOG_TRACE("Find signature!\n");
		}
	}

	bool HookUtility::updateAddrUnused()
	{
		return searchUnused();
	}

	bool HookUtility::searchSignature()
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
		m_sigMatched = true;
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
			LOG_ERROR("Cannot find signature of VerifyJIT\n");
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
			LOG_ERROR("Cannot find signature of ResolveMethodInfo\n");
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
			LOG_ERROR("Cannot find signature of GetMethodName\n");
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
			LOG_ERROR("Cannot find signature of Parse\n");
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
			LOG_ERROR("Cannot find signature of SetJIT\n");
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
			LOG_ERROR("Cannot find signature of Unused\n");
			return false;
		}
		m_addrUnused = searched;
		return true;
	}

}