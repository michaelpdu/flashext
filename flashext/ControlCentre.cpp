#include "ControlCentre.h"
#include "Logger.h"
#include "Utility.h"
#include "HookUtility.h"
#include "wdbgexts.h"

#include <boost/algorithm/string.hpp>
#include <vector>

namespace md
{

	ControlCentre* ControlCentre::s_instance = NULL;

	ControlCentre::ControlCentre(void)
		: m_iDbgCli(NULL)
		, m_iDbgCtl(NULL)
		, m_iDbgAdv(NULL)
		, m_bpEnable(false)
		, m_saveUnusedBuf(false)
		, m_pUnusedBuf(NULL)
        , m_dbgFlags(DBG_FLAGS_NO_TARGET)
	{
		m_pUnusedBuf = new char[sc_unusedSize];
		memset(m_pUnusedBuf,'\0',sc_unusedSize);
	}

	ControlCentre::~ControlCentre(void)
	{
		delete[] m_pUnusedBuf;
		m_pUnusedBuf = NULL;
		m_saveUnusedBuf = false;
	}

	ControlCentre* ControlCentre::getInstance()
	{
		if (!s_instance) {
			s_instance = new(std::nothrow) ControlCentre();
		}
		return s_instance;
	}

	void ControlCentre::releaseInstance()
	{
		if (!s_instance) {
			delete s_instance;
			s_instance = NULL;
		}
	}

	bool ControlCentre::initialize()
	{
		HRESULT hResult = S_FALSE;
		if (DebugCreate(__uuidof(IDebugClient), (void**) &m_iDbgCli) != S_OK)
		{
			LOG_ERROR("[CCInit] Acuqiring IDebugClient* Failed\n\n");
			return false;
		}
		if (m_iDbgCli->QueryInterface(__uuidof(IDebugControl), (void**) &m_iDbgCtl) != S_OK)
		{
			LOG_ERROR("[CCInit] Acuqiring IDebugControl* Failed\n\n");
			return false;
		}
		if (m_iDbgCli->QueryInterface(__uuidof(IDebugAdvanced), (void**) &m_iDbgAdv) != S_OK)
		{
			LOG_ERROR("[CCInit] Acuqiring IDebugAdvanced* Failed\n\n");
			return false;
		}
		if (m_iDbgCli->QueryInterface(__uuidof(IDebugDataSpaces), (void**) &m_iDbgData) != S_OK)
		{
			LOG_ERROR("[CCInit] Acuqiring IDebugDataSpaces* Failed\n\n");
			return false;
		}

		// set event callback
		if (!m_dbgEvent.initialize()) {
			LOG_ERROR("[CCInit] Initialize Debug Event Failed\n\n");
			return false;
		}
		if (m_iDbgCli->SetEventCallbacks(&m_dbgEvent) != S_OK)
		{
			LOG_ERROR("[CCInit] Set Event Callbacks Failed\n\n");
			return false;
		}

		return true;
	}

	bool ControlCentre::finalize()
	{
		m_dbgEvent.finalize();

		m_iDbgData->Release();
		m_iDbgAdv->Release();
		m_iDbgCtl->Release();
		m_iDbgCli->Release();

		return true;
	}

	void ControlCentre::setFirstBp()
	{
		IDebugBreakpoint *bpParse = md::Utility::setBreakpoint(md::HookUtility::getInstance()->getAddrParse());
	}

	bool ControlCentre::modifyControlFlow()
	{
		LOG_TRACE("Modify control flow\n");
		md::HookUtility* hu = md::HookUtility::getInstance();
		if (!hu) {
			LOG_ERROR("Faild to get HookUtility\n");
			return false;
		}
		// get setjit addr
		ULONG64 addrSetJIT = hu->getAddrSetJIT();
		// get getMethodName addr
		ULONG64 addrGetMethodName = hu->getAddrGetMethodName();
		// update addr of unused area
		if (!hu->updateAddrUnused()) {
			LOG_ERROR("Failed to update unused address\n");
			return false;
		}
		// search CCCCCCCC addr
		ULONG64 addrUnused = hu->getAddrUnused();
		// modify setjit
		//.text:106D7E80 8B 4C 24 08                                   mov     ecx, [esp+code]
		//.text:106D7E84 56                                            push    esi
		//.text:106D7E85 8B 74 24 08                                   mov     esi, [esp+4+mi]
		//.text:106D7E89 8B 46 30                                      mov     eax, [esi+30h]		--> 0x51,0x56,0x90
		//.text:106D7E8C 25 FF FF 7F FF                                and     eax, 0FF7FFFFFh		--> 0xE9,OFFSET
		//.text:106D7E91 0D 00 00 20 80                                or      eax, 80200000h
		//.text:106D7E96 56                                            push    esi
		
		//push ecx // 0x51
		//push esi // 0x56
		//0x90
		//jmp 0x******** //0xE9
		char bufJmp2Unused[] = {0x51,0x56,0x90,0xE9,0x00,0x00,0x00,0x00};
		LONG64 offset = Utility::calcOffset(addrSetJIT+0xC, addrUnused);
		if (offset == 0) {
			LOG_ERROR("Calculate offset failed\n");
			return false;
		}
		if (!Utility::writeOffset2Mem(offset, bufJmp2Unused+0x04, 4)) { // support 32 bit only
			LOG_ERROR("Write offset to memory failed\n");
			return false;
		}
		if (!WriteMemory(addrSetJIT+9,bufJmp2Unused,sizeof(bufJmp2Unused),NULL)) {
			LOG_ERROR("Modify setJIT code failed\n");
			return false;
		}
		// double check?
		
		// modify unused area
		//mov ecx,esi // 0x89,0xf1
		//// offset = 106C4750 - 1000ee4a - 5 = 6B5901
		//call 0x******** // 0xE8,0x01,0x59,0x6b,0x00
		//pop  esi // 0x5E
		//pop ecx // 0x59
		//mov eax,[esi+30h] // 0x8B,0x46,0x30
		//add eax,0xFF7FFFFF // 0x25,0xFF,0xFF,0x7F,0xFF
		//// offset = 106d7e91 - 1000ee59 - 5 = 6C9033
		//jmp 0x******** // 0xE9,0x33,0x90,0x6C,0x00
		char bufUnused[] = {0x89,0xF1,0xE8,0x00,0x00,0x00,0x00,0x5E,0x59,
			0x8B,0x46,0x30,0x25,0xFF,0xFF,0x7F,0xFF,0xE9,0x00,0x00,0x00,0x00};
		offset = Utility::calcOffset(addrUnused+0x02, addrGetMethodName);
		if (offset == 0) {
			LOG_ERROR("Calculate offset failed\n");
			return false;
		}
		if (!Utility::writeOffset2Mem(offset, bufUnused+0x03, 4)) { // support 32 bit only
			LOG_ERROR("Write offset to memory failed\n");
			return false;
		}
		offset = Utility::calcOffset(addrUnused+0x11, addrSetJIT+0x11);
		if (offset == 0) {
			LOG_ERROR("Calculate offset failed\n");
			return false;
		}
		if (!Utility::writeOffset2Mem(offset, bufUnused+0x12, 4)) { // support 32 bit only
			LOG_ERROR("Write offset to memory failed\n");
			return false;
		}
		if (!WriteMemory(addrUnused,bufUnused,sizeof(bufUnused),NULL)) {
			LOG_ERROR("Modify unused area failed\n");
			return false;
		}

		// save unused addr and content for checking
		memcpy(m_pUnusedBuf, bufUnused, sc_unusedSize);
		m_saveUnusedBuf = true;

		return true;
	}

	bool ControlCentre::checkPreviousModification()
	{
		try {
			ULONG64 addrUnused = md::HookUtility::getInstance()->getAddrUnused();
			if (0 == addrUnused) {
				LOG_TRACE("Not search unused area\n");
				return false;
			}
			if (!m_saveUnusedBuf) {
				LOG_TRACE("Not save unused buffer\n");
				return false;
			}
			LOG_TRACE("Unused area address: " << std::hex << addrUnused << std::endl);
			char buf[22] = {0};
			if (!ReadMemory(addrUnused,buf,sizeof(buf),NULL)) {
				LOG_ERROR("Read memory of unused area failed\n");
				return false;
			}
			LOG_TRACE("Read memory successfully\n");
			if(0 != memcmp(buf,m_pUnusedBuf,sizeof(22))) {
				LOG_ERROR("Content of unused area is changed\n");
				return false;
			}
			LOG_TRACE("Buffers are equal\n");
			return true;
		} catch (std::exception& e) {
			LOG_ERROR("Exception in CheckPreviousModification, "
				<< e.what() << std::endl);
			return false;
		}
	}

	void ControlCentre::setCustomBpInfo(const std::string& methodName, const std::string& cmd)
	{
		m_bpEnable = true;
		m_bpMethodName = methodName;
        m_bpCmd = cmd;
	}

	bool ControlCentre::getCustomBpMethodName(std::string& methodName, std::string& cmd)
	{
		if (!m_bpEnable) {
			return false;
		}
		methodName = m_bpMethodName;
        cmd = m_bpCmd;
		return true;
	}

    bool ControlCentre::SetCustomBpByCache(const std::string& methodName, const std::string& cmd)
    {
        DWORD entry = getEntry(methodName);
        if (!entry) return false;
        Utility::setBreakpoint(entry, DEBUG_BREAKPOINT_ENABLED, cmd);
        return true;
    }

    void ControlCentre::insertData(DWORD entry, const std::string& name)
    {
        m_tvHelper.insertData(entry,name);
    }

	std::string ControlCentre::getName(DWORD entry)
	{
		return m_tvHelper.getMethodNameByEntry(entry);
	}

	DWORD ControlCentre::getEntry(const std::string& name)
	{
		return m_tvHelper.getEntryByMethodName(name);
	}

	void ControlCentre::dumpMethodData()
	{
		m_tvHelper.dumpData();
	}

    void ControlCentre::printNearSymbol(ULONG64 addr)
    {
        m_tvHelper.printNearSymbol(addr);
    }

	void ControlCentre::removeBp(IDebugBreakpoint* bp) {
		if (S_OK != m_iDbgCtl->RemoveBreakpoint(bp)) {
			LOG_ERROR("Remove breakpoint failed, try to disable it\n");
			ULONG flags;
			bp->GetFlags(&flags);
			bp->SetFlags(flags & ~DEBUG_BREAKPOINT_ENABLED);
		}
	}

}