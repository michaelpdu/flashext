#include "MappingHelper.h"
#include "wdbgexts.h"
#include "Logger.h"
#include <sstream>

namespace md
{

	MappingHelper::MappingHelper(void)
	{
	}

	MappingHelper::~MappingHelper(void)
	{
		m_unmapEntry2MethodName.clear();
		m_unmapMethodName2Entry.clear();
	}

	//std::string MappingHelper::fakeName(DWORD index, DWORD mindex) {
	//	std::stringstream ssfakename;
	//	ssfakename << "abcindex_" << index << "_mindex_" << mindex;
	//	return ssfakename.str();
	//}

	//void MappingHelper::insertMethodInfo(DWORD index, DWORD mindex, DWORD nindex, DWORD info, DWORD entry)
	//{
	//	m_data.push_back(MappingData(index, mindex, nindex, info, entry));
	//}

	//void MappingHelper::bindFakeNameWithMinfo(const std::string& fakename, DWORD info)
	//{
	//	//for (std::vector<MappingData>::iterator iter = m_data.begin();
	//	//	iter != m_data.end(); ++iter)
	//	//{
	//	//	if (!iter->infoModified && iter->methodIndex == mindex && iter->abcIndex == index) {
	//	//		iter->methodInfo = info;
	//	//		iter->infoModified = true;
	//	//		break;
	//	//	}
	//	//}
	//	m_mapFakeName2Minfo.insert(std::make_pair(fakename, info));
	//	m_mapMinfo2FakeName.insert(std::make_pair(info,fakename));
	//}

	//bool MappingHelper::bindFakeNameWithEntry(DWORD info, DWORD entry)
	//{
	//	//for (std::vector<MappingData>::iterator iter = m_data.begin();
	//	//	iter != m_data.end(); ++iter)
	//	//{
	//	//	if (!iter->entryModified && iter->methodInfo == info && iter->abcIndex == index) {
	//	//		iter->methodEntry = entry;
	//	//		iter->entryModified = true;
	//	//		mindex = iter->methodIndex;
	//	//		return true;
	//	//	}
	//	//}
	//	auto iter = m_mapMinfo2FakeName.find(info);
	//	if (iter == m_mapMinfo2FakeName.end()) {
	//		LOG_TRACE("Cannot find info: " << std::hex << info << std::endl);
	//		return false;
	//	}
	//	m_mapFakeName2Entry.insert(std::make_pair(iter->second, entry));
	//	m_mapEntry2FakeName.insert(std::make_pair(entry, iter->second));

	//	return true;
	//}

	void MappingHelper::insertData(DWORD entry, const std::string& name)
	{
		m_unmapEntry2MethodName.insert(std::make_pair(entry,name));
		m_unmapMethodName2Entry.insert(std::make_pair(name,entry));
        m_mapEntry2MethodName.insert(std::make_pair(entry,name));
	}

	DWORD MappingHelper::getEntryByMethodName(const std::string& name)
	{
		auto iter = m_unmapMethodName2Entry.find(name);
		if (iter == m_unmapMethodName2Entry.end()) {
			LOG_TRACE("Cannot find entry by name: " << name << std::endl);
			return 0;
		}
		return iter->second;
	}

	std::string MappingHelper::getMethodNameByEntry(DWORD entry)
	{
		auto iter = m_unmapEntry2MethodName.find(entry);
		if (iter == m_unmapEntry2MethodName.end()) {
			LOG_TRACE("Cannot find name by entry: " << std::hex << entry << std::endl);
			return "NotFound";
		}
		return iter->second;
	}

	void MappingHelper::dumpData()
	{
		LOG_INFO("Dump Method Info Data\n"
			<< "Item Count = " << m_unmapEntry2MethodName.size() << std::endl
			<< "EntryAddr\tMethodName\n");
		for (auto iter = m_unmapEntry2MethodName.begin();
			iter != m_unmapEntry2MethodName.end(); ++iter)
		{
			LOG_INFO(std::hex << iter->first << "\t" << iter->second << std::endl);
		}
	}

    void MappingHelper::printNearSymbol(ULONG64 addr)
    {
        ULONG64 nearAddr = 0;
        std::string nearMethodName;
        for (auto iter = m_mapEntry2MethodName.begin();
            iter != m_mapEntry2MethodName.end(); ++iter)
        {
            //LOG_INFO("Entry: " << std::hex << iter->first
            //    << ", Method Name: " << iter->second << std::endl);
            if (iter->first == addr) {
                LOG_INFO("Match JIT Method, entry: " << std::hex << addr
                    << ", method name: " << iter->second << std::endl);
                return;
            }
            if (iter->first < addr) {
                nearAddr = iter->first;
                nearMethodName = iter->second;
                continue;
            } else {
                LOG_INFO("Find Near Method, address: " << std::hex << nearAddr
                    << "+0x" << std::hex << (addr-nearAddr)
                    << ", method name: " << nearMethodName << std::endl);
                return;
            }
        }
    }

}
