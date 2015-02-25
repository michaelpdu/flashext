#include "Utility.h"
#include "Logger.h"
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

IDebugBreakpoint* Utility::setBreakpoint(ULONG64 addr, ULONG flag, const std::string& cmd)
{
	LOG_TRACE("Set Breakpoint on " << std::hex << addr << std::endl);
	IDebugBreakpoint *bp = NULL;
	IDebugControl* dbgCtrl = ControlCentre::getInstance()->getDbgCtrl();
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
		LOG_ERROR(e.what() << std::endl);
		return false;
	}
}

}
