#pragma once
#include <basetsd.h>
#include "ControlCentre.h"
#include "Logger.h"

namespace md
{

	struct VB_INFO
	{
		DWORD addr;
		DWORD size;
		DWORD mcpSrc;
		DWORD mcpSize;

		VB_INFO(): addr(0), size(0), mcpSrc(0), mcpSize(0) {}
	};

class Utility
{
public:
	Utility(void);
	~Utility(void);

public:
	static IDebugBreakpoint* setBp(ULONG64 addr,
		ULONG flag = DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY,
		const std::string& cmd = "");

	static IDebugBreakpoint* setBpByName(const std::string& addrSymbol);

	static LONG64 calcOffset(ULONG64 curAddr, ULONG64 targetAddr);

	static bool writeOffset2Mem(LONG64 offset, char* buf, unsigned int size);

	static std::string logLevel2Str(LOGLEVEL level);
};

}
