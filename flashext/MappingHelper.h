#pragma once

#include <vector>
#include <map>
#include <objbase.h>
#include "boost/unordered_map.hpp"

namespace md
{

    class MappingHelper
    {
    public:
        MappingHelper(void);
        ~MappingHelper(void);

    public:
        void insertData(DWORD entry, const std::string& name);

        DWORD getEntryByMethodName(const std::string& name);
        std::string getMethodNameByEntry(DWORD entry);

        void dumpData();
        void printNearSymbol(ULONG64 addr);

    private:
        boost::unordered_map<std::string, DWORD> m_unmapMethodName2Entry;
        boost::unordered_map<DWORD, std::string> m_unmapEntry2MethodName;
        std::map<DWORD, std::string> m_mapEntry2MethodName;
    };

}