#pragma once

#include <windows.h>
#include <imagehlp.h>
#include <wdbgexts.h>
#include <dbgeng.h>
#include <extsfns.h>

#include "FPDebugEvent.h"
//#include "FPDebugOutput.h"
#include "MappingHelper.h"
//#include "BreakpointMgr.h"
#include "Logger.h"

#include<boost/unordered_map.hpp>

namespace md
{

    const DWORD DBG_FLAGS_NO_TARGET = 0x00000000;
    const DWORD DBG_FLAGS_SET_JIT   = 0x00000001;

class ControlCentre
{
public:
	static ControlCentre* getInstance();
	static void releaseInstance();

	~ControlCentre(void);

	bool initialize();
	bool finalize();

	void setFirstBp();

	IDebugClient* getDbgClient() {return m_iDbgCli;}
	IDebugControl* getDbgCtrl() {return m_iDbgCtl;}
	IDebugAdvanced* getDbgAdv() {return m_iDbgAdv;}
	IDebugDataSpaces* getDbgData() {return m_iDbgData;}

public:
	bool modifyControlFlow();
	bool checkPreviousModification();

    // custom breakpoint
	bool getCustomBpStatus() {return m_bpEnable;}
	void setCustomBpInfo(const std::string& methodName, const std::string& cmd = "");
	bool getCustomBpMethodName(std::string& methodName, std::string& cmd);
    bool SetCustomBpByCache(const std::string& methodName, const std::string& cmd = "");

    // JIT method information
    void insertData(DWORD entry, const std::string& name);
	std::string getName(DWORD entry);
	DWORD getEntry(const std::string& name);
    void dumpMethodData();
    void printNearSymbol(ULONG64 addr);

	void removeBp(IDebugBreakpoint* bp);

    // debug
    void setDbgFlags(DWORD flags) {
        m_dbgFlags |= flags;
        LOG_DEBUG("Set debug flags = " << m_dbgFlags << std::endl);
    }
    DWORD getDbgFlags() {return m_dbgFlags;}

private:
	ControlCentre(void);

private:
	static ControlCentre* s_instance;

	IDebugClient* m_iDbgCli;
	IDebugControl* m_iDbgCtl;
	IDebugAdvanced* m_iDbgAdv;
	IDebugDataSpaces* m_iDbgData;

	FPDebugEvent m_dbgEvent;
	MappingHelper m_tvHelper;

	// breakpoints info
	bool m_bpEnable;
	std::string m_bpMethodName;
    std::string m_bpCmd;

	// signature code for getting method name
	bool m_saveUnusedBuf;
	char* m_pUnusedBuf;
	static const unsigned int sc_unusedSize = 22;

    // debug
    DWORD m_dbgFlags;

};

}