/************************************************************
* 
*                 Flash Debug Extensions
*
*              michael_du@trendmicro.com.cn
*
************************************************************/

#include "ControlCentre.h"
#include "HookUtility.h"
#include "Logger.h"
#include "boost/algorithm/string.hpp"
#include <boost/algorithm/string/regex.hpp>

/***********************************************************
* Global Variable Needed For Functions
***********************************************************/              
WINDBG_EXTENSION_APIS ExtensionApis = {0};


/***********************************************************
* Global Variable Needed For Versioning
***********************************************************/              
EXT_API_VERSION g_ExtApiVersion = {
	1 ,
	1 ,
	EXT_API_VERSION_NUMBER ,
	0
} ;


/***********************************************************
* DllMain
*
* Purpose: Entry point to dynamic link library.
*
*  Parameters:
*     Handle To Module Instance, Reason For Calling, Reserved
*
*  Return Values:
*     TRUE for success
*     FALSE for error
*
***********************************************************/              
BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, PVOID pReserved)
{
	if (DLL_PROCESS_ATTACH == dwReason) {

	} else if (DLL_PROCESS_DETACH == dwReason) {
		md::ControlCentre* ctrCentre = md::ControlCentre::getInstance();
		if (!ctrCentre) {
			return false;
		}
		if (!ctrCentre->finalize()) {
			return false;
		}
		ctrCentre->releaseInstance();
		md::Logger::getInstance()->releaseInstance();
	}
	return TRUE;
}

/***********************************************************
* ExtensionApiVersion
*
* Purpose: WINDBG will call this function to get the version
*          of the API
*
*  Parameters:
*     Void
*
*  Return Values:
*     Pointer to a EXT_API_VERSION structure.
*
***********************************************************/              
LPEXT_API_VERSION WDBGAPI ExtensionApiVersion (void)
{
	return &g_ExtApiVersion;
}

/***********************************************************
* WinDbgExtensionDllInit
*
* Purpose: WINDBG will call this function to initialize
*          the API
*
*  Parameters:
*     Pointer to the API functions, Major Version, Minor Version
*
*  Return Values:
*     Nothing
*
***********************************************************/              
VOID WDBGAPI WinDbgExtensionDllInit (PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
	ExtensionApis = *lpExtensionApis;

	md::Logger::getInstance()->setLevel(LOGLEVEL_INFO);
	md::ControlCentre* ctrCentre = md::ControlCentre::getInstance();
	if (!ctrCentre) {
		return ;
	}
	if (!ctrCentre->initialize()) {
		return ;
	}

}

/***********************************************************
* !help
*
* Purpose: WINDBG will call this API when the user types !help
*          
*
*  Parameters:
*     N/A
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (help)
{
	LOG_INFO("Flash Debug Extensions Usage:" << std::endl
	<< "!help               - Get these help information" << std::endl
	<< "!base <address>     - Set base address of flash player" << std::endl
	<< "!tjit               - Trace JIT functions" << std::endl
	<< "!bpjit <method_name> [<condition>]" << std::endl
    << "                    - Set breakpoint on JIT function by name" << std::endl
	<< "!lnjit <address>    - Get mapping of JIT function entry and name" << std::endl
	<< "!dump               - Get mapping of JIT function entry and name" << std::endl
	<< std::endl);
}

/***********************************************************
* !base
*
* Purpose: Set base address of flash player, default value is 0x10000000
*
*  Usage:
*     !base <address>
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (base)
{
	//LOG_WARN("[base] Not Implemented!\n");
	ULONG64 addr = GetExpression(args);
	LOG_INFO("Set base address: " << std::hex << addr << std::endl);
	md::HookUtility::getInstance()->setBaseAddress(addr);
}

/***********************************************************
* !tjit
*
* Purpose: track all jited function
*
*  Usage:
*     !tjit
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (tjit)
{
	md::ControlCentre* cc = md::ControlCentre::getInstance();
	if (!cc) {
		LOG_ERROR("Failed to get control center");
	}
    LOG_INFO("Prepare to trace JIT" << std::endl);
    DWORD dbgFlags = cc->getDbgFlags();
    if (!dbgFlags) {
        LOG_DEBUG("Set log level to LOGLEVEL_MSG" << std::endl);
	    md::Logger::getInstance()->setLevel(LOGLEVEL_MSG);
    } else {
        LOG_DEBUG("In debug mode, debug flags:" << dbgFlags << std::endl);
    }
	cc->setFirstBp();
}

/***********************************************************
* !lnjit
*
* Purpose: displays the JIT symbols at or near the given address
*
*  Usage:
*     !lnjit <address>
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (lnjit)
{
    //LOG_WARN("Not Implemented!\n");
    ULONG64 addr = GetExpression(args);
    LOG_INFO("parameter: " << std::hex << addr << std::endl);
    md::ControlCentre* cc = md::ControlCentre::getInstance();
    if (!cc) {
        LOG_ERROR("Failed to get control center");
    }
    cc->printNearSymbol(addr);
}


/***********************************************************
* !wtjit
*
* Purpose: watch and track all jited function
*
*  Usage:
*     !wtjit
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (wtjit)
{
	LOG_WARN("Not Implemented!\n");
	//md::ControlCentre::getInstance()->
}

DECLARE_API (loglevel)
{
	//LOG_WARN("[loglevel] Not Implemented!\n");
	DWORD level = GetExpression(args);
	LOG_INFO("Set loglevel: " << level << std::endl);
	md::Logger::getInstance()->setLevel((LOGLEVEL)level);
}

/***********************************************************
* !bpjit
*
* Purpose: set breakpoint on jited function
*
*  Usage:
*     !bpjit <function name> [ --> <condition>]
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (bpjit)
{
	LOG_INFO("parameter: " << args << std::endl);

    std::string argInput(args);
    std::vector<std::string> argInfo;
    boost::algorithm::trim(argInput);
    boost::algorithm::split_regex(argInfo,argInput,boost::regex("[\s]*-->[\s]*"));
    if (argInfo.size() > 2) {
        LOG_ERROR("invalid arguments, check usage");
        return;
    }

    std::string cmd;
    if (argInfo.size() == 2) {
        cmd = argInfo[1];
    }

	md::ControlCentre* cc = md::ControlCentre::getInstance();
	if (!cc) {
		LOG_ERROR("Failed to get control center");
	}
    if (cc->getCustomBpStatus() && cc->SetCustomBpByCache(argInfo[0],cmd)) {
        return;
    }

    cc->setCustomBpInfo(argInfo[0],cmd);
    cc->setFirstBp();
}

/***********************************************************
* !dump
*
* Purpose: get mapping information
*
*  Usage:
*     !dump
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (dump)
{
	md::ControlCentre::getInstance()->dumpMethodData();
}

DECLARE_API (test)
{
	//std::string output;
	//md::ControlCentre::getInstance()->getOutput(output);
	//LOG_TRACE(output);
}

DECLARE_API (debug)
{
    LOG_INFO("parameter: " << args << std::endl);
    if (0 == stricmp(args, "setjit")) {
        md::Logger::getInstance()->setLevel(LOGLEVEL_DEBUG);
        md::ControlCentre::getInstance()->setDbgFlags(md::DBG_FLAGS_SET_JIT);
    } else {
        LOG_WARN("DON'T SUPPOT THIS DEBUG ARGS\n");
    }
}