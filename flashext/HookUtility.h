#pragma once

#include <stdarg.h>
#include <objbase.h>

namespace md
{

class HookUtility
{
public:
	static HookUtility* getInstance();
	~HookUtility(void);

private:
	HookUtility(void);

public:
	ULONG64 getAddrParse() {return m_addrParse;}
	void setAddrParse(ULONG64 addr) {m_addrParse = addr;}

	//ULONG64 getAddrMethodInfo() {return m_addrMethodInfo;}
	//void setAddrMethodInfo(ULONG64 addr) {m_addrMethodInfo = addr;}

	ULONG64 getAddrResolveMethodInfo() {return m_addrResolveMethodInfo;}
	void setAddrResolveMethodInfo(ULONG64 addr) {m_addrResolveMethodInfo = addr;}

	ULONG64 getAddrVerifyJIT() {return m_addrVerifyJIT;}
	void setAddrVerifyJIT(ULONG64 addr) {m_addrVerifyJIT = addr;}

	ULONG64 getAddrGetMethodName() {return m_addrGetMethodName;}
	void setAddrGetMethodName(ULONG64 addr) {m_addrGetMethodName = addr;}

	void setBaseAddress(ULONG64 addr);

	ULONG64 getAddrSetJIT() {return m_addrSetJIT;}
	ULONG64 getAddrUnused() {return m_addrUnused;}

    ULONG64 getAddrAnalyzeEmbedded() {return m_addrAnalyzeEmbedded;}

	ULONG64 getAddrAcroMalloc() {return m_addrAcroMalloc;}
	ULONG64 getAddrAcroMcp1() {return m_addrAcroMcp1;}
	ULONG64 getAddrAcroMcp2() {return m_addrAcroMcp2;}

	bool updateAddrUnused();

public:
	bool searchRdSig();

private:
	bool searchFPSignature();

	bool searchVerifyJIT();
	bool searchResolveMethodInfo();
	bool searchParse();
	bool searchGetMethodName();
	bool searchSetJIT();
	bool searchUnused();

    bool searchAnalyzeEmbedded();

	// AcroRd
	bool searchAcroMalloc();
	bool searchAcroMcp1();
	bool searchAcroMcp2();

private:
	static HookUtility s_instance;
	
	ULONG64 m_addrParse;
	ULONG64 m_addrGetMethodName;
	ULONG64 m_addrResolveMethodInfo; // in AbcParser::parseMethodBodies
	ULONG64 m_addrVerifyJIT; // in BaseExecMgr::verifyMethod

	ULONG64 m_addrUnused;
	ULONG64 m_addrSetJIT;

    ULONG64 m_addrAnalyzeEmbedded;

	// bass address of FP
	ULONG64 m_baseAddr;

	// AcroRd
	ULONG64 m_addrAcroMalloc;
	ULONG64 m_addrAcroMcp1;
	ULONG64 m_addrAcroMcp2;

	bool m_sigMatched;
};

}

#define HU md::HookUtility::getInstance()