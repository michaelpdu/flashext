#pragma once

#include <windows.h>
#include <imagehlp.h>
#include <wdbgexts.h>
#include <dbgeng.h>
#include <extsfns.h>

#include "FPDebugEvent.h"
#include "MappingHelper.h"
#include "Logger.h"

#include<boost/unordered_map.hpp>

#define CSTR_LOADBYTES_FUN_NAME "flash.display::Loader/loadBytes"

namespace md
{

    const DWORD DBG_FLAGS_NO_TARGET		= 0x00000000;
    const DWORD DBG_FLAGS_SET_JIT		= 0x00000001;
	const DWORD DBG_FLAGS_SET_LOGLEVEL  = 0x00000002;


class ControlCentre
{
public:
	static ControlCentre* getInstance();
	static void releaseInstance();

	~ControlCentre(void);

	bool initialize();
	bool finalize();

	void prepareEnv();
	void prepareEnv4ExportEmbedded();

    void prepareEnv4AHIA();
    

	IDebugClient* getDbgClient() {return m_iDbgCli;}
	IDebugControl* getDbgCtrl() {return m_iDbgCtl;}
	IDebugAdvanced* getDbgAdv() {return m_iDbgAdv;}
	IDebugDataSpaces* getDbgData() {return m_iDbgData;}
	IDebugSymbols* getDbgSym() {return m_iDbgSym;}

public:
	bool modifyControlFlow();
	bool checkPreviousModification();

    // custom breakpoint
	bool getCustomBpStatus() {return m_bpEnable;}
	void setCustomBpInfo(const std::string& methodName, const std::string& cmd = "");
	//bool getCustomBpMethodName(std::string& methodName, std::string& cmd);
    bool SearchCustomBpInCache(const std::string& methodName, const std::string& cmd = "");

    // JIT method information
    void insertData(DWORD entry, const std::string& name);
	std::string getName(DWORD entry);
	DWORD getEntry(const std::string& name);
    void dumpMethodData();
    void printNearSymbol(ULONG64 addr);

	void removeBp(IDebugBreakpoint* bp);

    // Export Embedded
    bool getExportEmbeddedStatus() {return m_exportEmbedded;}

    // debug
    void setDbgFlags(DWORD flags) {
        m_dbgFlags |= flags;
        LOG_DEBUG("Set debug flags = " << m_dbgFlags);
    }
    DWORD getDbgFlags() {return m_dbgFlags;}




    // insert a custom breakpoint into list
    void insertBpList(const std::string& name, IDebugBreakpoint* bp) {
        m_unmapCustomBp[name] = bp;
    }

    // get function name from BP list
    bool getFuncNameFromBpList(IDebugBreakpoint* bp, std::string& name) {
        for (auto iter = m_unmapCustomBp.begin(); iter != m_unmapCustomBp.end(); ++iter) {
            if (iter->second == bp) {
                LOG_DEBUG("Find breakpoint in Custom Breakpoint List, function name is \'" << iter->first << "\'");
                name = iter->first;
                return true;
            }
        }
        LOG_DEBUG("Cannot find breakpoint in Custom Breakpoint List");
        return false;
    }

    void listJitBp() {
        for (auto iter = m_unmapCustomBp.begin(); iter != m_unmapCustomBp.end(); ++iter) {
            std::string name = iter->first;
            ULONG id = 0;
            iter->second->GetId(&id);
            ULONG64 offset = 0;
            iter->second->GetOffset(&offset);
            LOG_INFO("[JIT Breakpoint] name = \'" << name << "\', id = " << id << ", offset = 0x" << std::hex << offset);
        }
    }





    // append JIT BP info <name, cmd>
    void appendJitBp(const std::string& name, const std::string& cmd) {
        m_unmapBpNameCmd[name] = cmd;
    }

    // hit JIT breakpoints
    bool hitJitBp(const std::string& name, std::string& cmd)
    {
        if (m_bpEnable) {
            for (auto iter = m_unmapBpNameCmd.begin(); iter != m_unmapBpNameCmd.end(); ++iter) {
                if (iter->first == name) {
                    LOG_DEBUG("Find specific function name in custom breakpoint list");
                    cmd = iter->second;
                    return true;
                }
            }
            LOG_DEBUG("Cannot find specific function name in custom breakpoint list");
            return false;
        } else {
            LOG_DEBUG("Custom breakpoint is disable");
            return false;
        }
    }


	// AcroRd Heap Spray
	void dumpSprayResult();


private:
	ControlCentre(void);



private:
	static ControlCentre* s_instance;

	IDebugClient* m_iDbgCli;
	IDebugControl* m_iDbgCtl;
	IDebugAdvanced* m_iDbgAdv;
	IDebugDataSpaces* m_iDbgData;
	IDebugSymbols* m_iDbgSym;

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

    // export embedded
    bool m_exportEmbedded;

    // debug
    DWORD m_dbgFlags;

    // custom breakpoint list
    boost::unordered_map<std::string, IDebugBreakpoint*> m_unmapCustomBp;
    boost::unordered_map<std::string, std::string> m_unmapBpNameCmd;
};

}

#define CC md::ControlCentre::getInstance()
