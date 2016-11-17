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
#include <boost/format.hpp>
#include "boost/algorithm/string.hpp"
#include <boost/algorithm/string/regex.hpp>

// virtual alloc block size
#define VB_SIZE_THRESHOLD 0x7E000

namespace md
{

FPDebugEvent::FPDebugEvent(void)
	: m_refCount(0)
	, m_uiParseHit(0)
	, m_bResetHardcodeBP(false)
    , m_addrLoadBytesEntry(0)
    , m_findLoadBytesEntry(false)
	, m_cc(NULL)
	, m_dbgAdv(NULL)
	, m_dbgCtrl(NULL)
	, m_dbgData(NULL)
    , m_dbgClient(NULL)
	, m_offsetRtlFreeHeap(0)
{
}

FPDebugEvent::~FPDebugEvent(void)
{
}

bool FPDebugEvent::initialize()
{
	m_cc = CC;
	if (!m_cc) {
		LOG_ERROR("[FPDebugEvent] Cannot get control centre");
		return false;
	}

	m_dbgAdv = m_cc->getDbgAdv();
	m_dbgCtrl = m_cc->getDbgCtrl();
	m_dbgData = m_cc->getDbgData();
    m_dbgClient = m_cc->getDbgClient();

	CC->getDbgSym()->GetOffsetByName("ntdll!RtlFreeHeap", &m_offsetRtlFreeHeap);

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
	//LOG_TRACE("Set breakpoint at ResolveMethodInfo");
	//IDebugBreakpoint *bpMethodID = Utility::setBp(HU->getAddrResolveMethodInfo());

	//// set breakpoint VerifyJIT
	//LOG_TRACE("Set breakpoint at VerifyJIT");
	//IDebugBreakpoint *bpVerifyJIT = Utility::setBp(HU->getAddrVerifyJIT());

	LOG_TRACE("Set breakpoint at SetJIT");
	IDebugBreakpoint *bpSetJIT = Utility::setBp(HU->getAddrSetJIT());
}

//void FPDebugEvent::handleResolveMethodInfo()
//{
//	CONTEXT ctx;
//	if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx)))
//	{
//		LOG_ERROR("[BP Handler][MethodID] Get thread context{1} failed");
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
//			LOG_ERROR("[BP Handler][VerifyJIT] Get thread context failed");
//			break;
//		}
//		DWORD methodInfo = ctx.Esi;
//		unsigned int buf[4] = {0};
//		if (S_OK != m_dbgData->ReadVirtual(ctx.Esi, buf, sizeof(buf), NULL) ) {
//			LOG_ERROR("[BP Handler][VerifyJIT] Read virtual addr failed");
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
//				Utility::setBp(methodEntry, DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ADDER_ONLY);
//			}
//		}
//	} while(0);
//
//	return DEBUG_STATUS_GO;
//}

void FPDebugEvent::handleSetJIT()
{
	LOG_TRACE("Handle SetJIT");
	if (!m_cc->checkPreviousModification()) {
		if (!m_cc->modifyControlFlow()) {
			LOG_ERROR("Modify control flow failed");
		} else {
			LOG_TRACE("Modify control flow successfully");
		}
	} else {
		LOG_TRACE("Find previous modification");
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
		LOG_ERROR("Failed to execute \'p;p;p;p;p;p;p;p;p;p;p;p\' ");
		return;
	}

	CONTEXT ctx;
	if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx)))
	{
		LOG_ERROR("Failed to get thread context, code and mi");
		return;
	}
	LOG_TRACE("Method Info: " << std::hex << ctx.Esi
		<< ", Entry Code: " << std::hex << ctx.Ecx);

	ULONG64 addrStr = 0;
    ULONG sizeStr = 0;
	if (!ReadMemory(ctx.Eax+8,&addrStr,4,NULL)) {
		LOG_ERROR("Failed to read memory, address of method name");
		return;
	}

	if (0 == addrStr) {
		LOG_DEBUG("Process intern string");
        
        // read intern string
        ULONG64 addrInternStr = 0;
        if (!ReadMemory(ctx.Eax+0xC,&addrInternStr,4,NULL)) {
            LOG_ERROR("Failed to read memory, address of intern string");
            return;
        }
        if (0 == addrInternStr) {
            LOG_DEBUG("Intern string address is NULL");
            return;
        }

        // read flags
        ULONG64 bitsAndFlags = 0;
        if (!ReadMemory(ctx.Eax+0x14,&bitsAndFlags,4,NULL)) {
            LOG_ERROR("Failed to read memory, bits and flags");
            return;
        }

        if (0x04 != bitsAndFlags) {
            LOG_DEBUG("Intern string flags != 0x04, flags: " << bitsAndFlags);
            return;
        }

        // read method name in intern string
        DWORD internBuf[5] = {0};
        if (!ReadMemory(addrInternStr,&internBuf,sizeof(internBuf),NULL)) {
            LOG_ERROR("Failed to read memory, intern string");
            return;
        }

        addrStr = internBuf[2];
	}

    if (!ReadMemory(ctx.Eax+0x10,&sizeStr,4,NULL)) {
        LOG_ERROR("Failed to read memory, size of method name");
        return;
    }

	LOG_TRACE("Method name, address: " << std::hex << addrStr
        << "size: " << std::hex << sizeStr);

	char* pMethodName = new(std::nothrow) char[sizeStr+1];
	if (NULL == pMethodName) {
		LOG_ERROR("Failed to allocate memory for method name");
		return ;
	}
	memset(pMethodName, '\0', sizeStr+1);
	if (!ReadMemory(addrStr,pMethodName,sizeStr,NULL)) {
		LOG_ERROR("Failed to read memory, method name");
		return;
	}
	LOG_MSG("JIT Entry: " << std::hex << ctx.Ecx << ", Method Name: " << pMethodName);

	// save method_name & entry
    m_cc->insertData(ctx.Ecx, pMethodName);

	// set breakpoint
	std::string bpMethodName(pMethodName), bpCmd;
    if (CC->hitJitBp(bpMethodName, bpCmd))
	{
		LOG_DEBUG("Find JIT breakpoint, name = " << bpMethodName << ", cmd = " << bpCmd);
        if ( CC->getExportEmbeddedStatus() && bpMethodName == CSTR_LOADBYTES_FUN_NAME) {
            m_addrLoadBytesEntry = ctx.Ecx;
        }

		IDebugBreakpoint* bp = Utility::setBp(ctx.Ecx, DEBUG_BREAKPOINT_ENABLED, bpCmd);
        CC->insertBpList(bpMethodName, bp);
	}

    delete pMethodName;
    pMethodName = NULL;
}

void FPDebugEvent::handleAnalyzeEmbedded()
{
    LOG_INFO("Enter into handleAnalyzeEmbedded");
    CONTEXT ctx;
    if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx)))
    {
        LOG_ERROR("[handleAnalyzeEmbedded] Failed to get thread context");
        return;
    }

    // poi(ESP+4): address of embedded content
    // poi(ESP+8): length of embedded content
    DWORD espData[3] = {0};
    if (!ReadMemory(ctx.Esp,&espData,sizeof(espData),NULL)) {
        LOG_ERROR("[handleAnalyzeEmbedded] Failed to read memory, ESP data");
        return;
    }

    std::string cmd = str(boost::format(".writemem c:\\embedded_0x%08x_0x%x.bin %x L%x") % espData[1] % espData[2] % espData[1] % espData[2]);
    LOG_INFO("Execute CMD: " << cmd );
    if (S_OK != CC->getDbgCtrl()->Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd.c_str(), DEBUG_EXECUTE_ECHO)) {
        LOG_ERROR("[handleAnalyzeEmbedded] Failed to execute command: " << cmd );
    } else {
        LOG_INFO("Export Successfully!");
    }
}


void FPDebugEvent::callbackAcroMalloc()
{
	CONTEXT ctx;
	if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx)))
	{
		LOG_ERROR("[callbackAcroMalloc] Failed to get thread context");
		return;
	}

	// EDI: malloc size
	// EAX: allocated address
	if (ctx.Edi > VB_SIZE_THRESHOLD) {
		LOG_DEBUG(boost::format("Allocate virtual block, size = 0x%x, address = 0x%08x") % ctx.Edi % ctx.Eax);

		VB_INFO vb;
		vb.addr = ctx.Eax;
		vb.size = ctx.Edi;

		// 
		auto iterVBInfo = m_mapVB.find(ctx.Eax);
		if (iterVBInfo == m_mapVB.end())
		{
			m_mapVB[ctx.Eax] = vb;
		}

		//
		auto iter = m_histAllocVBSize.find(ctx.Edi);
		if ( iter == m_histAllocVBSize.end() ) {
			m_histAllocVBSize[ctx.Edi] = 1;
		} else {
			m_histAllocVBSize[ctx.Edi] ++;
		}

		m_preAllocVBSize = ctx.Edi;
		m_preAllocVBAddr = ctx.Eax;
	}
}

void FPDebugEvent::callbackAcroMcp()
{
	CONTEXT ctx;
	if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx)))
	{
		LOG_ERROR("[callbackAcroMcp] Failed to get thread context");
		return;
	}

	// poi(ESP)  : dest 
	// poi(ESP+4): src
	// poi(ESP+8): size

	DWORD espData[3] = {0};
	if (!ReadMemory(ctx.Esp,&espData,sizeof(espData),NULL)) {
		LOG_ERROR("Failed to read memory, ESP data");
		return;
	}
	if (espData[2] > VB_SIZE_THRESHOLD) {
		LOG_DEBUG(boost::format("Copy memory from [0x%08x] to [0x%08x], size = 0x%x") % espData[1] % espData[0] % espData[2]);

		//
		auto iter = m_histMcpSrc.find(espData[1]);
		if ( iter == m_histMcpSrc.end() ) {
			m_histMcpSrc[espData[1]] = 1;
		} else {
			m_histMcpSrc[espData[1]] ++;
		}

		//
		auto iterVB1 = m_mapVB.find(espData[0]); // search node by dest
		if (iterVB1 != m_mapVB.end()) {
			auto iterVB2 = m_mapVB.find(espData[1]); // search node by src
			if (iterVB2 != m_mapVB.end()) { // find copy chain, update mcpSrc and mcpSize
				iterVB1->second.mcpSrc = iterVB2->second.mcpSrc; 
				iterVB1->second.mcpSize = (iterVB1->second.mcpSize < iterVB2->second.mcpSize) ? iterVB1->second.mcpSize : iterVB2->second.mcpSize;
			} else {
				iterVB1->second.mcpSrc = espData[1];
				iterVB1->second.mcpSize = espData[2];
			}
		}

		m_preMcpDest = espData[0];
		m_preMcpSrc = espData[1];
		m_preMcpSize = espData[2];
	}
}

void FPDebugEvent::callbackRtlFreeHeap()
{
	CONTEXT ctx;
	if (S_OK != m_dbgAdv->GetThreadContext(&ctx, sizeof(ctx)))
	{
		LOG_ERROR("[callbackRtlFreeHeap] Failed to get thread context");
		return;
	}

	// poi(ESP+4): heap handle 
	// poi(ESP+8): flags
	// poi(ESP+C): heap base

	DWORD espData[3] = {0};
	if (!ReadMemory(ctx.Esp+4,&espData,sizeof(espData),NULL)) {
		LOG_ERROR("Failed to read memory, ESP data");
		return;
	}

	if ((espData[2]-20) % 0x10000 == 0) {
		auto iter = m_mapVB.find(espData[2]);
		if ( iter != m_mapVB.end() ) {
			m_mapVB.erase(iter);
		}
	}
}

void FPDebugEvent::dumpSprayResult()
{
	if (0 == m_histAllocVBSize.size() && 0 == m_histMcpSrc.size()) {
		LOG_INFO("Cannot find HEAP SPRAY behavior!");
		return;
	}
	
	DWORD totalSize = 0;
	LOG_INFO("\n===== Histogram for Allocated Virtual Block SIZE =====");
	for (auto iter = m_histAllocVBSize.begin(); iter != m_histAllocVBSize.end(); ++iter)
	{
		totalSize += iter->first * iter->second;
		LOG_INFO(boost::format(">>> Size = 0x%08x, Count = %d") % iter->first % iter->second);
	}

	LOG_INFO("\n===== Histogram for memcpy from SOURCE =====");
	for (auto iter = m_histMcpSrc.begin(); iter != m_histMcpSrc.end(); ++iter)
	{
		LOG_INFO(boost::format(">>> Source = 0x%08x, Count = %d") % iter->first % iter->second);
	}

	LOG_INFO("\n===== Statistic for Virtual Blocks =====");
	totalSize = 0;
	boost::unordered::unordered_map<DWORD, DWORD> histVBSizeCount;
	boost::unordered::unordered_map<DWORD, DWORD> histMcpSrcCount;
	boost::unordered::unordered_map<DWORD, DWORD> histMcpSizeCount;
	for (auto iter = m_mapVB.begin(); iter != m_mapVB.end(); ++iter)
	{
		// calculate total size
		totalSize += iter->second.size;

		// hist for virtual block size
		if ( histVBSizeCount.find(iter->second.size) == histVBSizeCount.end() ) {
			histVBSizeCount[iter->second.size] = 1;
		} else {
			histVBSizeCount[iter->second.size]++;
		}

		// hist for memory copy source
		if ( histMcpSrcCount.find(iter->second.mcpSrc) == histMcpSrcCount.end() ) {
			histMcpSrcCount[iter->second.mcpSrc] = 1;
		} else {
			histMcpSrcCount[iter->second.mcpSrc]++;
		}

		// hist for memory copy size
		if ( histMcpSizeCount.find(iter->second.mcpSize) == histMcpSizeCount.end() ) {
			histMcpSizeCount[iter->second.mcpSize] = 1;
		} else {
			histMcpSizeCount[iter->second.mcpSize]++;
		}
	}

	LOG_INFO(boost::format(">>> Total Virtual Block Size = %dM") % (totalSize/1048576));
	for (auto iter = histVBSizeCount.begin(); iter != histVBSizeCount.end(); ++iter)
	{
		LOG_INFO(boost::format(">>> Size = 0x%x, Count = %d") % iter->first % iter->second);
	}
	LOG_INFO("");
	for (auto iter = histMcpSrcCount.begin(); iter != histMcpSrcCount.end(); ++iter)
	{
		LOG_INFO(boost::format(">>> MCP Source = 0x%08x, Count = %d") % iter->first % iter->second);
	}
	LOG_INFO("");
	for (auto iter = histMcpSizeCount.begin(); iter != histMcpSizeCount.end(); ++iter)
	{
		LOG_INFO(boost::format(">>> MCP Size = 0x%x, Count = %d") % iter->first % iter->second);
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
		ULONG64 offset = 0;
		if (S_OK == Bp->GetOffset(&offset)) {
            LOG_TRACE("Enter into bp handler, offset = " << std::hex << offset);
            
            ULONG flags = 0;
            Bp->GetFlags(&flags);
            LOG_TRACE("Breakpoint flags = " << flags);

            std::string name;
            bool isJitBp = false;
            if (CC->getFuncNameFromBpList(Bp, name)) {
                isJitBp = true;
                LOG_TRACE("It's JIT breakpoint, name = " << name );
                ULONG id = 0;
                Bp->GetId(&id);
                LOG_INFO("[Breakpoint] name = \'" << name << "\', id = " << id << ", offset = 0x" << std::hex << offset );
            } else {
                LOG_TRACE("It's not JIT breakpoint");
            }

            // Flash Player Hook Points
			if (HU->getAddrParse() == offset) {
				m_uiParseHit++;
				LOG_TRACE("Breakpoint(AbcParser::parse) hits = " << m_uiParseHit << ", m_bResetHardcodeBP = " << m_bResetHardcodeBP);
				if (m_uiParseHit > 2 && !m_bResetHardcodeBP) {
					addHardcodeBreakpoints();
					m_bResetHardcodeBP = true;
				}
				break;
			} else if (HU->getAddrSetJIT() == offset) {
				handleSetJIT();
                if (m_cc->getDbgFlags() & md::DBG_FLAGS_SET_JIT) {
                    LOG_TRACE("[SetJIT] Return DEBUG_STATUS_BREAK");
				    return DEBUG_STATUS_BREAK;
                }
                LOG_TRACE("[SetJIT] Break out");
				break;
			} else if (HU->getAddrAnalyzeEmbedded() == offset) {
                if (m_findLoadBytesEntry) {
                    handleAnalyzeEmbedded();
                }
                break;
            } else if (CC->getExportEmbeddedStatus() && m_addrLoadBytesEntry == offset) {
                LOG_INFO("Find entry for loadBytes");
                m_findLoadBytesEntry = true;
                break;
            }

            // AcroRd Hook Points
            else if (HU->getAddrAcroMalloc() == offset) {
				callbackAcroMalloc();
				break;
			} else if (HU->getAddrAcroMcp1() == offset || HU->getAddrAcroMcp2() == offset) {
				callbackAcroMcp();
				break;
			} else if (m_offsetRtlFreeHeap == offset) {
				callbackRtlFreeHeap();
				break;
			}
            
            
            else {
                
                if (isJitBp)
                {
                    char cmdBuf[MAX_PATH] = {0};
                    ULONG cmdLen = 0;
                    if (S_OK == Bp->GetCommand(cmdBuf, MAX_PATH, &cmdLen)) {
                        LOG_TRACE("CMD content: " << cmdBuf);
                        std::string argInput(cmdBuf);
                        std::vector<std::string> cmdInfo;
                        boost::algorithm::trim(argInput);
                        boost::algorithm::split_regex(cmdInfo,argInput,boost::regex(";"));

                        for (auto iter = cmdInfo.begin(); iter != cmdInfo.end(); ++iter)
                        {
                            LOG_TRACE("CMD: " << *iter );
                        }
                        
                        //CC->getDbgCtrl()->Execute();
                        if ("g" == *cmdInfo.end() || "gc" == *cmdInfo.end()) {
                            LOG_TRACE("Return DEBUG_STATUS_GO when custom cmd ends with \'g\' or \'gc\'");
                            return DEBUG_STATUS_GO;
                        } else {
                            LOG_TRACE("Return DEBUG_STATUS_BREAK when find JIT breakpoint");
                            return DEBUG_STATUS_BREAK;
                        }

                    } else {
                        LOG_TRACE("Return DEBUG_STATUS_BREAK when find JIT breakpoint and get command failed");
                        return DEBUG_STATUS_BREAK;
                    }
                }

				IDebugClient* dbgClient = NULL;
				if (S_OK == Bp->GetAdder(&dbgClient) && dbgClient)
				{
					LOG_TRACE("Get Current BP Client = " << dbgClient << ", Main Client = " << m_dbgClient);
					if (dbgClient != m_dbgClient) {
                        LOG_TRACE("Return DEBUG_STATUS_NO_CHANGE");
						return DEBUG_STATUS_NO_CHANGE;
					}
				}
				break;
			}
		}
	} while(0);

    LOG_TRACE("Return DEBUG_STATUS_GO");
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
	//LOG_TRACE("ModuleLoad: %p %p, Module Name: %s",
	//	BaseOffset, BaseOffset+ModuleSize, ModuleName);

	//if (boost::starts_with(ModuleName,"Flash")) {
	//	HU->setBaseAddress(BaseOffset);

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