/************************************************************
* 
*                 Flash Debug Extensions
*
*              michael_du@trendmicro.com.cn
*
************************************************************/

#include "ControlCentre.h"
#include "HookUtility.h"
#include "Utility.h"
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
		if (!CC) {
			return false;
		}
		if (!CC->finalize()) {
			return false;
		}
		CC->releaseInstance();
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
	if (!CC) {
		return ;
	}
	if (!CC->initialize()) {
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
	<< "!loglevel <level>   - Set loglevel in extension, default value is LOGLEVEL_INFO(3)" << std::endl
	<< "                    - Other level:" << std::endl
	<< "                        LOGLEVEL_TRACE = 0" << std::endl
	<< "                        LOGLEVEL_DEBUG = 1" << std::endl
	<< "                        LOGLEVEL_MSG   = 2" << std::endl
	<< "!dump <arg>         - arg is one of following options:" << std::endl 
	<< "                      method_data - Get mapping of JIT function entry and name" << std::endl
	<< "                      spray_info  - Get spray information about AcroRd" << std::endl
	<< "--------------------------------------------------------------------------------" << std::endl
	<< "!base <address>     - Set base address of flash player" << std::endl
	<< "!tjit               - Trace JIT functions" << std::endl
	<< "!bpjit <method_name> [<condition>]" << std::endl
    << "                    - Set breakpoint on JIT function by name" << std::endl
    << "!go                 - Prepare environment and go" << std::endl
    << "!bljit              - List breakpoints in JIT list" << std::endl
	<< "!lnjit <address>    - Displays JIT symbols at or near given address" << std::endl
    << "!export_embedded    - Export embedded content" << std::endl
	<< "--------------------------------------------------------------------------------" << std::endl
	<< "!ahia               - Analyze Heapspray in AcroRd" << std::endl);
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
	//LOG_WARN("[base] Not Implemented!");
	ULONG64 addr = GetExpression(args);
	LOG_INFO("Set base address: " << std::hex << addr);
	HU->setBaseAddress(addr);
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
	if (!CC) {
		LOG_ERROR("Failed to get control center");
	}
    LOG_INFO("Prepare to trace JIT");
    DWORD dbgFlags = CC->getDbgFlags();
    if (!dbgFlags) {
        LOG_DEBUG("Set log level to LOGLEVEL_MSG");
	    md::Logger::getInstance()->setLevel(LOGLEVEL_MSG);
    } else {
        LOG_DEBUG("In debug mode, debug flags:" << dbgFlags);
    }
	CC->prepareEnv();
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
    //LOG_WARN("Not Implemented!");
    ULONG64 addr = GetExpression(args);
    LOG_INFO("parameter: " << std::hex << addr);

    if (!CC) {
        LOG_ERROR("Failed to get control center");
    }
    CC->printNearSymbol(addr);
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
	LOG_WARN("Not Implemented!");
}

DECLARE_API (loglevel)
{
	//LOG_WARN("[loglevel] Not Implemented!");
	DWORD level = GetExpression(args);
	LOG_INFO("Set loglevel: " << md::Utility::logLevel2Str((LOGLEVEL)level));
	CC->setDbgFlags(md::DBG_FLAGS_SET_LOGLEVEL);
	if ( level < LOGLEVEL_TRACE || level > LOGLEVEL_OFF ) {
		level = LOGLEVEL_INFO;
	}

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
	LOG_INFO("parameter: " << args);

    std::string argInput(args);
    std::vector<std::string> argInfo;
    boost::algorithm::trim(argInput);
    boost::algorithm::split_regex(argInfo,argInput,boost::regex("-->"));
    LOG_TRACE("Args length: " << argInfo.size());
    if (argInfo.size() > 2) {
        LOG_ERROR("invalid arguments, check usage");
        return;
    }

    LOG_TRACE("Method Name: " << argInfo[0] );

    std::string cmd;
    if (argInfo.size() == 2) {
        cmd = argInfo[1];
        LOG_TRACE("CMD: " << cmd );
    }

	if (!CC) {
		LOG_ERROR("Failed to get control center");
	}
    if (CC->getCustomBpStatus() && CC->SearchCustomBpInCache(argInfo[0],cmd)) {
        return;
    }

    CC->setCustomBpInfo(argInfo[0],cmd);
    //CC->prepareEnv();
}


DECLARE_API (bljit)
{
    if (!CC) {
        LOG_ERROR("Failed to get control center");
    }
    CC->listJitBp();
}

DECLARE_API (go)
{
    if (!CC) {
        LOG_ERROR("Failed to get control center");
    }
    CC->prepareEnv();

    LOG_INFO("Execute !go");
    if (S_OK != CC->getDbgCtrl()->Execute(DEBUG_OUTCTL_THIS_CLIENT, "g", DEBUG_EXECUTE_ECHO)) {
        LOG_ERROR("[GO] Failed to execute command: !go");
    }
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
	LOG_INFO("parameter: " << args);
	if ( 0 == stricmp(args, "method_data") ) {
		CC->dumpMethodData();
	} else if ( 0 == stricmp(args, "spray_info") ) {
		CC->dumpSprayResult();
	}
}

DECLARE_API (test)
{
	//std::string output;
	//CC->getOutput(output);
	//LOG_TRACE(output);
}

DECLARE_API (debug)
{
    LOG_INFO("parameter: " << args);
    if (0 == stricmp(args, "setjit")) {
        md::Logger::getInstance()->setLevel(LOGLEVEL_DEBUG);
        CC->setDbgFlags(md::DBG_FLAGS_SET_JIT);
    } else {
        LOG_WARN("DON'T SUPPOT THIS DEBUG ARGS");
    }
}








/***********************************************************
* !ahia
*
* Purpose: analyze heapspray behavior in AcroRd
*
*  Usage:
*     !ahia
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (ahia)
{
	if (!CC) {
		LOG_ERROR("Failed to get control center");
	}
	LOG_INFO("Prepare to analyze heapspray behavior in AcroRd");
	DWORD dbgFlags = CC->getDbgFlags();
	if (!dbgFlags) {
		LOG_DEBUG("Set log level to LOGLEVEL_MSG");
		md::Logger::getInstance()->setLevel(LOGLEVEL_MSG);
	} else {
		LOG_DEBUG("In debug mode, debug flags:" << dbgFlags);
	}
	CC->prepareEnv4AHIA();
}


/***********************************************************
* !export_embedded
*
* Purpose: export embedded flash
*
*  Usage:
*     !export_embedded
*
*  Return Values:
*     N/A
*
***********************************************************/
DECLARE_API (export_embedded)
{
    LOG_INFO("Prepare to export embedded content!");
    CC->prepareEnv4ExportEmbedded();
}





