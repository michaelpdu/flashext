#include "FPDebugEvent.h"
#include "wdbgexts.h"
#include "HookUtility.h"
#include "ControlCentre.h"
#include "Utility.h"
#include "Logger.h"

#include <Windows.h>
#include <string>
#include <sstream>

#include <boost/algorithm/string/predicate.hpp>

namespace md
{

FPDebugEvent::FPDebugEvent(void)
	: m_refCount(0)
	, m_uiParseHit(0)
	, m_bResetHardcodeBP(false)
	, m_cc(NULL)
	, m_dbgAdv(NULL)
	, m_dbgCtrl(NULL)
	, m_dbgData(NULL)
    , m_dbgClient(NULL)
{
}

FPDebugEvent::~FPDebugEvent(void)
{
}

bool FPDebugEvent::initialize()
{
	m_cc = ControlCentre::getInstance();
	if (!m_cc) {
		LOG_ERROR("[FPDebugEvent] Cannot get control centre");
		return false;
	}

	m_dbgAdv = m_cc->getDbgAdv();
	m_dbgCtrl = m_cc->getDbgCtrl();
	m_dbgData = m_cc->getDbgData();
    m_dbgClient = m_cc->getDbgClient();

	return true;
}

bool FPDebugEvent::finalize()
{
	//if (m_dbgAdv) {
	//	m_dbgAdv->Release();
	//}
	//if (m_dbgCtrl) {
	//	m_dbgCtrl->Release();
	//}
	//if (m_dbgData) {
	//	m_dbgData->Release();
	//}

	return true;
}

void FPDebugEvent::addHardcodeBreakpoints()
{
	//// set breakpoint ResolveMethodInfo
	//LOG_TRACE("Set breakpoint at ResolveMethodInfo\n");
	//IDebugBreakpoint *bpMethodID = Utility::setBreakpoint(HookUtility::getInstance()->getAddrResolveMethodInfo());

	//// set breakpoint VerifyJIT
	//LOG_TRACE("Set breakpoint at VerifyJIT\n");
	//IDebugBreakpoint *bpVerifyJIT = Utility::setBreakpoint(HookUtility::getInstance()->getAddrVerifyJIT());

	LOG_TRACE("Set breakpoint at SetJIT\n");
	IDebugBreakpoint *bpSetJIT = Utility::setBreakpoint(HookUtility::getInstance()->getAddrSetJIT());
}

//void FPDebugEvent::handleResolveMethodInfo()
//{
//	CONTEXT ctx;
//	if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx)))
//	{
//		LOG_ERROR("[BP Handler][MethodID] Get thread context{1} failed\n");
//		return ;
//	} 
//
//	DWORD methodIndex = ctx.Edi;
//	DWORD methodInfo = ctx.Ebx;
//	m_cc->modifyMethodInfoByMethodIndex(m_uiParseHit, methodIndex, methodInfo);
//}

//HRESULT FPDebugEvent::handleVerifyJIT()
//{
//	do {
//		CONTEXT ctx;
//		if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx))) {
//			LOG_ERROR("[BP Handler][VerifyJIT] Get thread context failed\n");
//			break;
//		}
//		DWORD methodInfo = ctx.Esi;
//		unsigned int buf[4] = {0};
//		if (S_OK != m_dbgData->ReadVirtual(ctx.Esi, buf, sizeof(buf), NULL) ) {
//			LOG_ERROR("[BP Handler][VerifyJIT] Read virtual addr failed\n");
//			break;
//		}
//		DWORD methodEntry = buf[1];
//		bool ret = m_cc->modifyMethodEntryByInfo(m_uiParseHit, methodInfo, methodEntry);
//
//		// enable custom breakpoint
//		if (ret && m_cc->getCustomBpStatus()) {
//			DWORD cstBpIndex = 0, cstBpMindex = 0;
//			m_cc->getNumericBpInfo(cstBpIndex, cstBpMindex);
//			if (MappingHelper::fakeName(cstBpIndex, cstBpMindex) == m_cc->getName(methodEntry)) {
//				Utility::setBreakpoint(methodEntry, DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY);
//			}
//		}
//	} while(0);
//
//	return DEBUG_STATUS_GO;
//}

void FPDebugEvent::handleSetJIT()
{
	LOG_TRACE("Handle SetJIT\n");
	if (!m_cc->checkPreviousModification()) {
		if (!m_cc->modifyControlFlow()) {
			LOG_ERROR("Modify control flow failed\n");
		} else {
			LOG_TRACE("Modify control flow successfully\n");
		}
	} else {
		LOG_TRACE("Find previous modification\n");
	}

	//106d7e80 8b4c2408        mov     ecx,dword ptr [esp+8] ss:0023:020dcdd0=05d25d9d
	//106d7e84 56              push    esi
	//106d7e85 8b742408        mov     esi,dword ptr [esp+8]
	//106d7e89 51              push    ecx
	//106d7e8a 56              push    esi
	//106d7e8b 90              nop
	//106d7e8c e9f26addff      jmp     Flash32_16_0_0_257!DllUnregisterServer+0x2cb4e5 (104ae983)
	//106d7e91 0d00002080      or      eax,80200000h

	//104ae983 89f1            mov     ecx,esi
	//104ae985 e8c65d2100      call    Flash32_16_0_0_257!IAEModule_IAEKernel_UnloadModule+0x144c80 (106c4750)
	//104ae98a 5e              pop     esi
	//104ae98b 59              pop     ecx
	//104ae98c 8b4630          mov     eax,dword ptr [esi+30h]			<----
	//104ae98f 25ffff7fff      and     eax,0FF7FFFFFh
	//104ae994 e9f8942200      jmp     Flash32_16_0_0_257!IAEModule_IAEKernel_UnloadModule+0x1583c1 (106d7e91)

	if (S_OK != m_dbgCtrl->Execute(
		DEBUG_OUTCTL_THIS_CLIENT/* | DEBUG_OUTCTL_OVERRIDE_MASK | DEBUG_OUTCTL_NOT_LOGGED*/,
		"p;p;p;p;p;p;p;p;p;p;p;p",
		DEBUG_EXECUTE_DEFAULT) )
	{
		LOG_ERROR("Failed to execute \'p;p;p;p;p;p;p;p;p;p;p;p\'\n");
		return;
	}
	CONTEXT ctx;
	if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx)))
	{
		LOG_ERROR("Failed to get thread context, code and mi\n");
		return;
	}
	LOG_TRACE("Method Info: " << std::hex << ctx.Esi
		<< ", Entry Code: " << std::hex << ctx.Ecx << std::endl);

	ULONG64 addrStr = 0;
    ULONG sizeStr = 0;
	if (!ReadMemory(ctx.Eax+8,&addrStr,4,NULL)) {
		LOG_ERROR("Failed to read memory, address of method name\n");
		return;
	}

	if (0 == addrStr) {
		LOG_DEBUG("Process intern string\n");
        
        // read intern string
        ULONG64 addrInternStr = 0;
        if (!ReadMemory(ctx.Eax+0xC,&addrInternStr,4,NULL)) {
            LOG_ERROR("Failed to read memory, address of intern string\n");
            return;
        }
        if (0 == addrInternStr) {
            LOG_DEBUG("Intern string address is NULL\n");
            return;
        }

        // read flags
        ULONG64 bitsAndFlags = 0;
        if (!ReadMemory(ctx.Eax+0x14,&bitsAndFlags,4,NULL)) {
            LOG_ERROR("Failed to read memory, bits and flags\n");
            return;
        }

        if (0x04 != bitsAndFlags) {
            LOG_DEBUG("Intern string flags != 0x04, flags: " << bitsAndFlags
                << std::endl);
            return;
        }

        // read method name in intern string
        DWORD internBuf[5] = {0};
        if (!ReadMemory(addrInternStr,&internBuf,sizeof(internBuf),NULL)) {
            LOG_ERROR("Failed to read memory, intern string\n");
            return;
        }

        addrStr = internBuf[2];
	}

    if (!ReadMemory(ctx.Eax+0x10,&sizeStr,4,NULL)) {
        LOG_ERROR("Failed to read memory, size of method name\n");
        return;
    }

	LOG_TRACE("Method name, address: " << std::hex << addrStr
        << "size: " << std::hex << sizeStr << std::endl);

	char* pMethodName = new(std::nothrow) char[sizeStr+1];
	if (NULL == pMethodName) {
		LOG_ERROR("Failed to allocate memory for method name\n");
		return ;
	}
	memset(pMethodName, '\0', sizeStr+1);
	if (!ReadMemory(addrStr,pMethodName,sizeStr,NULL)) {
		LOG_ERROR("Failed to read memory, method name\n");
		return;
	}
	LOG_MSG("JIT Entry: " << std::hex << ctx.Ecx
		<< ", Method Name: " << pMethodName << std::endl);

	// save method_name & entry
    m_cc->insertData(ctx.Ecx, pMethodName);

	// set breakpoint
	std::string bpMethodName, bpCmd;
	if (m_cc->getCustomBpStatus()
        && m_cc->getCustomBpMethodName(bpMethodName, bpCmd)
		&& 0 == strcmp(bpMethodName.c_str(), pMethodName) )
	{
		LOG_DEBUG("Find custom breakpoint\n");
		Utility::setBreakpoint(ctx.Ecx, DEBUG_BREAKPOINT_ENABLED, bpCmd);
	}
}

STDMETHODIMP FPDebugEvent::QueryInterface(
        THIS_
        __in REFIID InterfaceId,
        __out PVOID* Interface
        )
{
	*Interface = NULL;
	if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
		IsEqualIID(InterfaceId, __uuidof(IDebugEventCallbacks)))
	{
		*Interface = (IDebugEventCallbacks *)this;
		AddRef();
		return S_OK;
	}
	else
	{
		return E_NOINTERFACE;
	}
}

STDMETHODIMP_(ULONG) FPDebugEvent::AddRef(
        THIS
        )
{
	return /*++m_refCount*/1;
}

STDMETHODIMP_(ULONG) FPDebugEvent::Release(
        THIS
        )
{
	return /*--m_refCount*/0;
}

STDMETHODIMP FPDebugEvent::GetInterestMask(
        THIS_
        __out PULONG Mask
        )
{
	*Mask = DEBUG_EVENT_BREAKPOINT/* | DEBUG_EVENT_LOAD_MODULE*/;
	return S_OK;
}

STDMETHODIMP FPDebugEvent::Breakpoint(
        THIS_
        __in PDEBUG_BREAKPOINT Bp
        )
{
	do {
		//ULONG 
		//StackTrace (
		//ULONG FramePointer,
		//ULONG StackPointer,
		//ULONG ProgramCounter,
		//PEXTSTACKTRACE StackFrames,
		//ULONG Frames
		//);

		//ULONG framePointer = 0, stackPointer = 0, programCounter = 0;
		//EXTSTACKTRACE stackFrames;
		//ULONG frame = StackTrace(framePointer, stackPointer, programCounter, &stackFrames, 20);
		//if (frame >= 9)
		//	break;

		ULONG64 offset = 0;
		if (S_OK == Bp->GetOffset(&offset)) {
			LOG_TRACE("Enter into bp handler, offset = " << std::hex << offset << std::endl);

			if (HookUtility::getInstance()->getAddrParse() == offset) {
				m_uiParseHit++;
				LOG_TRACE("Breakpoint(AbcParser::parse) hits " << m_uiParseHit << std::endl);
				if (m_uiParseHit > 2 && !m_bResetHardcodeBP) {
					addHardcodeBreakpoints();
					//if (!m_cc->modifyControlFlow()) {
					//	LOG_ERROR("Modify control flow failed\n");
					//} else {

					//}
					m_bResetHardcodeBP = true;
				}
			} /*else if (HookUtility::getInstance()->getAddrResolveMethodInfo() == offset) {
				handleResolveMethodInfo();
				break;
			} else if (HookUtility::getInstance()->getAddrVerifyJIT() == offset) {
				handleVerifyJIT();
				break;
			} */else if (HookUtility::getInstance()->getAddrSetJIT() == offset) {
				handleSetJIT();
                if (m_cc->getDbgFlags() & md::DBG_FLAGS_SET_JIT) {
				    return DEBUG_STATUS_BREAK;
                }
				break;
			} else {
				IDebugClient* dbgClient = NULL;
				if (S_OK == Bp->GetAdder(&dbgClient) && dbgClient)
				{
					//LOG_TRACE("Get Debug Client = " << dbgClient << ", Main Client = " << m_dbgClient << std::endl);

					////char buf[1024] = {0};
					////ULONG outSize = 0;
					////if (S_OK == Bp->GetCommand(buf, 1023, &outSize)) {
					////	LOG_TRACE("CMD: %s\n",buf);
					////}

					if (m_dbgClient-dbgClient == 1) {
					//	LOG_TRACE("This Breakpoint is set in current Debug Client\n");
					//	if (m_cc->getTraceStatus()) {
					//		unsigned count = m_cc->queryBpCount(Bp);
					//		LOG_TRACE("count = " << count << std::endl);
					//		if (!count) {
					//			m_cc->removeBp(Bp);
					//		} else {
					//			std::string name = m_cc->getName(offset);
					//			LOG_INFO("[JIT TRACE] " << name << ", offset = "
					//				<< std::hex << offset << std::endl);
					//		} 
					//		break;
					//	}

					//	LOG_TRACE("Return break!\n");
						return DEBUG_STATUS_BREAK;
					}

					return DEBUG_STATUS_NO_CHANGE;
				}
				else
				{
					LOG_ERROR("Get Debug Client Failed\n");
				}
			}
		}

	} while(0);

	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::Exception(
        THIS_
        __in PEXCEPTION_RECORD64 Exception,
        __in ULONG FirstChance
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::CreateThread(
        THIS_
        __in ULONG64 Handle,
        __in ULONG64 DataOffset,
        __in ULONG64 StartOffset
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::ExitThread(
        THIS_
        __in ULONG ExitCode
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::CreateProcess(
        THIS_
        __in ULONG64 ImageFileHandle,
        __in ULONG64 Handle,
        __in ULONG64 BaseOffset,
        __in ULONG ModuleSize,
        __in_opt PCSTR ModuleName,
        __in_opt PCSTR ImageName,
        __in ULONG CheckSum,
        __in ULONG TimeDateStamp,
        __in ULONG64 InitialThreadHandle,
        __in ULONG64 ThreadDataOffset,
        __in ULONG64 StartOffset
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::ExitProcess(
        THIS_
        __in ULONG ExitCode
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::LoadModule(
        THIS_
        __in ULONG64 ImageFileHandle,
        __in ULONG64 BaseOffset,
        __in ULONG ModuleSize,
        __in_opt PCSTR ModuleName,
        __in_opt PCSTR ImageName,
        __in ULONG CheckSum,
        __in ULONG TimeDateStamp
        )
{
	//LOG_TRACE("ModuleLoad: %p %p, Module Name: %s\n",
	//	BaseOffset, BaseOffset+ModuleSize, ModuleName);

	//if (boost::starts_with(ModuleName,"Flash")) {
	//	HookUtility::getInstance()->setBaseAddress(BaseOffset);

	//	return DEBUG_STATUS_BREAK;
	//}
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::UnloadModule(
        THIS_
        __in_opt PCSTR ImageBaseName,
        __in ULONG64 BaseOffset
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::SystemError(
        THIS_
        __in ULONG Error,
        __in ULONG Level
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::SessionStatus(
        THIS_
        __in ULONG Status
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::ChangeDebuggeeState(
        THIS_
        __in ULONG Flags,
        __in ULONG64 Argument
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::ChangeEngineState(
        THIS_
        __in ULONG Flags,
        __in ULONG64 Argument
        )
{
	return DEBUG_STATUS_GO;
}

STDMETHODIMP FPDebugEvent::ChangeSymbolState(
        THIS_
        __in ULONG Flags,
        __in ULONG64 Argument
        )
{
	return DEBUG_STATUS_GO;
}


}