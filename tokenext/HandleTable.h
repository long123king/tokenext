#pragma once
#include "usr_common.h"   
#include <functional>
using namespace std;

class ExtExtension;
extern ExtExtension* g_ExtInstancePtr;

class CHandleTable
{
public:
    CHandleTable(
        __in size_t levels,
        __in size_t l1Addr,
        __in size_t handleCount);
    ~CHandleTable();

    void 
    traverse(
        __in function<bool(size_t, size_t)> callback
        );

    size_t 
    remained()
    {
        return m_handleCount;
    }

private:
    size_t m_levels;
    size_t m_l1Addr;
    size_t m_handleCount;
};

