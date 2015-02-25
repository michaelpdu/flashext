#pragma once
#include <basetsd.h>
#include "ControlCentre.h"

namespace md
{

class Utility
{
public:
	Utility(void);
	~Utility(void);

public:
	static IDebugBreakpoint* setBreakpoint(ULONG64 addr,
		ULONG flag = DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY,
		const std::string& cmd = "");

	static LONG64 calcOffset(ULONG64 curAddr, ULONG64 targetAddr);

	static bool writeOffset2Mem(LONG64 offset, char* buf, unsigned int size);
};

}
