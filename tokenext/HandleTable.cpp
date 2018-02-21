#include "HandleTable.h"
#include "../inc/engextcpp10.hpp"

CHandleTable::CHandleTable(
    __in size_t levels,
    __in size_t l1Addr,
    __in size_t handleCount)
    :m_levels(levels)
    ,m_l1Addr(l1Addr)
    ,m_handleCount(handleCount)
{
}


CHandleTable::~CHandleTable()
{
}

void 
CHandleTable::traverse(
    __in function<bool(size_t, size_t)> callback
    )
{
    if (0 == m_levels)
    {
		uint8_t* this_page = new uint8_t[0x1000];
		if (S_OK == g_ExtInstancePtr->m_Data->ReadVirtual(m_l1Addr, this_page, 0x1000, NULL))
		{
			for (size_t i = 0; i < 256 && m_handleCount > 0; i++)
			{
				size_t entry = *(size_t*)(this_page + i * 0x10);
				size_t access = *(size_t*)(this_page + i * 0x10 + 0x08);

				callback(entry, access);
				m_handleCount--;
			}
		}

		delete[] this_page;

        //for (size_t i = 0; i < 256 && m_handleCount > 0; i++)
        //{
        //    size_t entry = 0;
        //    size_t access = 0;
        //    
        //    if (g_ExtInstancePtr &&
        //        S_OK == g_ExtInstancePtr->m_Data->ReadVirtual(m_l1Addr + i * 0x10, &entry, sizeof(size_t), NULL) &&
        //        S_OK == g_ExtInstancePtr->m_Data->ReadVirtual(m_l1Addr + i * 0x10 + 0x08, &access, sizeof(size_t), NULL) &&
        //        callback(entry, access))
        //        m_handleCount--;
        //        
        //}
    }
    else
    {
		uint8_t* this_page = new uint8_t[0x1000];
		if (S_OK == g_ExtInstancePtr->m_Data->ReadVirtual(m_l1Addr, this_page, 0x1000, NULL))
		{
			for (size_t i = 0; i < 512; i++)
			{
				size_t next_level_addr = *(size_t*)(this_page + i * 0x08);

				CHandleTable next_level_table(m_levels - 1, next_level_addr, m_handleCount);
				next_level_table.traverse(callback);
				m_handleCount = next_level_table.remained();
				if (m_handleCount == 0)
					break;
			}
		}

		delete[] this_page;

        //for (size_t i = 0; i < 512; i++)
        //{
        //    size_t next_level_addr = 0;
        //    if (g_ExtInstancePtr &&
        //        S_OK == g_ExtInstancePtr->m_Data->ReadVirtual(m_l1Addr + i * 0x08, &next_level_addr, sizeof(size_t), NULL))
        //    {
        //        //size_t processed_count = i * 256 * (1 << ((m_levels - 1 >= 0 ? m_levels - 1 : 0) * 8));
        //        CHandleTable next_level_table(m_levels - 1, next_level_addr, m_handleCount);
        //        next_level_table.traverse(callback);    
        //        m_handleCount = next_level_table.remained();
        //        if (m_handleCount == 0)
        //            break;
        //    }
        //}
    }
}
