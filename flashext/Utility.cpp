#include "Utility.h"
#include <sstream>
#include <math.h>

namespace md
{

Utility::Utility(void)
{
}


Utility::~Utility(void)
{
}

IDebugBreakpoint* Utility::setBp(ULONG64 addr, ULONG flag, const std::string& cmd)
{
	LOG_TRACE("[SetBp] Set Breakpoint on " << std::hex << addr);
	IDebugBreakpoint *bp = NULL;
	IDebugControl* dbgCtrl = CC->getDbgCtrl();
	if (S_OK != dbgCtrl->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp)) {
		LOG_ERROR("[BPJIT] Failed to add breakpoint");
		return NULL;
	}
	if (S_OK != bp->SetOffset(addr)) {
		LOG_ERROR("[BPJIT] Failed to set offset");
		return NULL;
	}
	if (S_OK != bp->AddFlags(flag)) {
		LOG_ERROR("[BPJIT] Failed to add flags");
		return NULL;
	}

	if (cmd.size() != 0) {
		if (S_OK != bp->SetCommand(cmd.c_str())) {
			LOG_ERROR("[BPJIT] Failed to set command");
			return NULL;
		}
	}
	return bp;
}

IDebugBreakpoint* Utility::setBpByName(const std::string& addrSymbol)
{
	LOG_TRACE("[SetBpByName] Set Breakpoint on " << addrSymbol);
	ULONG64 offset = 0;
	HRESULT result = CC->getDbgSym()->GetOffsetByName(addrSymbol.c_str(), &offset);
	switch(result)
	{
	case S_FALSE:
		LOG_ERROR("the name Symbol was not unique and multiple symbols with that name were found. One of these symbols was arbitrarily chosen and returned.");
		return NULL;
	case E_FAIL:
		LOG_ERROR("No symbol could be found with the specified name.");
		return NULL;
	}
	LOG_TRACE("Offset = " << std::hex << offset)
	return setBp(offset, DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY);
}

LONG64 Utility::calcOffset(ULONG64 curAddr, ULONG64 targetAddr)
{
	LONG64 offset = 0;
	if (abs((long long)(targetAddr - curAddr)) <= 5) {
		return offset;
	}

	//from low addr jump to hight addr
	//offset = high_addr - low_addr - 5
	//from high addr jump to low addr
	//offset = low_addr - high_addr -5
	return offset = targetAddr - curAddr - 5;
}

bool Utility::writeOffset2Mem(LONG64 offset, char* buf, unsigned int size)
{
	try {
		long long tmpOffset = offset;
		for (unsigned int i = 0; i < size; ++i) {
			buf[i] = (char)tmpOffset;
			tmpOffset >>= 8;
		}
		return true;
	} catch (std::exception& e) {
		LOG_ERROR("Exception in writeOffset2Mem(): " << e.what());
		return false;
	}
}

std::string Utility::logLevel2Str(LOGLEVEL level)
{
	//LOGLEVEL_OFF    = 6,
	//LOGLEVEL_ERROR  = 5,
	//LOGLEVEL_WARN   = 4,
	//LOGLEVEL_INFO   = 3,
	//LOGLEVEL_MSG    = 2,
	//LOGLEVEL_DEBUG  = 1,
	//LOGLEVEL_TRACE  = 0,

	std::string msg;
	switch (level)
	{
	case LOGLEVEL_OFF:
		msg = "LOGLEVEL_OFF";
		break;
	case LOGLEVEL_ERROR:
		msg = "LOGLEVEL_ERROR";
		break;
	case LOGLEVEL_WARN:
		msg = "LOGLEVEL_WARN";
		break;
	case LOGLEVEL_INFO:
		msg = "LOGLEVEL_INFO";
		break;
	case LOGLEVEL_MSG:
		msg = "LOGLEVEL_MSG";
		break;
	case LOGLEVEL_DEBUG:
		msg = "LOGLEVEL_DEBUG";
		break;
	case LOGLEVEL_TRACE:
		msg = "LOGLEVEL_TRACE";
		break;
	default:
		msg = "LOGLEVEL_INFO";
		break;
	}
	return msg;
}

}
