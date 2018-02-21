#include "TokenExt.h"   

#define FILTER_CATCH \
    catch (ExtException& e)     \
    {                            \
        Err("%s %s %d %s\n", __FILE__, __FUNCTION__, __LINE__, e.GetMessageA());       \
        /*ThrowRemote(e.GetStatus(), e.GetMessageA());      \ 
    */}                          \
    catch (exception& e)        \
    {           \
    Err("%s %s %d %s\n", __FILE__, __FUNCTION__, __LINE__, e.what());       \
    /*ThrowRemote(E_OUTOFMEMORY, e.what());   \
    */}
 
CTokenExt::CTokenExt()
    :m_header_cookie_addr(0)
    ,m_type_index_table_addr(0)
    ,m_ob_header_cookie(0)
   // ,m_args_regex(R"RAW((\w+)\s*(((?:0x)*[0-9a-fA-F]\+)|([0-9a-f]{8}'[0-9a-fA-F]{8})|(.*))*)RAW")
{ 
} 

void 
CTokenExt::initialize()
{
    static bool initialized = false;
    if (initialized)
        return;

    if (S_OK != m_Symbols->GetOffsetByName("nt!ObHeaderCookie", &m_header_cookie_addr) ||
        S_OK != m_Data->ReadVirtual(m_header_cookie_addr, &m_ob_header_cookie, sizeof(uint8_t), NULL))
    {
        Err("Fail to get the offset of nt!ObHeaderCookie\n");
        return;
    }

    if (S_OK != m_Symbols->GetOffsetByName("nt!ObTypeIndexTable", &m_type_index_table_addr))
    {
        Err("Fail to get the offset of nt!ObTypeIndexTable\n");
        return;
    }

    initialized = true;
}
 
void CTokenExt::dump_usage()
{
    Out("!dk cmd [address] [options]\n");
    Out("commands:\n");
    Out("%20s - %s\n", "pses", "dump all active processes");
    Out("%20s - %s\n", "gobj", "dump all global object, same as WinObj");
    Out("%20s - %s\n", "handles", "dump all open handles by a specific process");
    Out("%20s - %s\n", "khandles", "dump all kernle open handles");
    Out("%20s - %s\n", "types", "dump all object types");
    Out("%20s - %s\n", "dbgdata", "dump all debug data");
    Out("%20s - %s\n", "process", "dump a specific process");
    Out("%20s - %s\n", "obj", "dump a specific object header");
    Out("%20s - %s\n", "handle_table", "dump a specific process's handle table");
    Out("%20s - %s\n", "token", "dump a specific token");
    Out("%20s - %s\n", "sdr", "dump a specific security descriptor [relative]");
    Out("%20s - %s\n", "acl", "dump a specific acl");
    Out("%20s - %s\n", "sid", "dump a specific sid");
    Out("%20s - %s\n", "sessions", "dump all logon sessions");
    Out("options:\n");
    Out("%20s - %s\n", "/f", "dump all related fields in detail");
    Out("%20s - %s\n", "/po", "dump related process object header");
    Out("%20s - %s\n", "/to", "dump related token object header");
    Out("%20s - %s\n", "/r", "dump object directory recursively");
    Out("%20s - %s\n", "/o", "dump related object header");
    Out("%20s - %s\n", "/ht", "dump related handle table");
    Out("%20s - %s\n", "/token", "dump related token");
    Out("%20s - %s\n", "/link", "dump linked token");
    Out("%20s - %s\n", "/threads", "dump process related threads");
}

size_t CTokenExt::get_cr3()
{
	try
	{
		size_t proc_addr = curr_proc();

		size_t cr3 = read<size_t>(proc_addr + 0x28);

		return cr3;
	}
	FILTER_CATCH;

	return 0;
}

void CTokenExt::dump_modules()
{
    try
    {
        size_t lm_head_addr = readDbgDataAddr(DEBUG_DATA_PsLoadedModuleListAddr);

        ExtRemoteTypedList modules_list(lm_head_addr, "nt!_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks");
        for (modules_list.StartHead(); modules_list.HasNode(); modules_list.Next())
        {
            auto module = modules_list.GetTypedNode();
            size_t module_addr = modules_list.GetNodeOffset();

            size_t base_addr = module.Field("DllBase").GetUlongPtr();
            wstring full_name = readUnicodeString(module_addr + module.GetFieldOffset("FullDllName"));
            wstring base_name = readUnicodeString(module_addr + module.GetFieldOffset("BaseDllName"));
            size_t entry = module.Field("EntryPoint").GetUlongPtr();
            uint32_t size = module.Field("SizeOfImage").GetUlong();

            Out(L"0x%I64x [0x%016x] 0x%I64x %20s %s\n", base_addr, size, entry, base_name.c_str(), full_name.c_str());
        }
    }
    FILTER_CATCH;
}

void CTokenExt::dump_size(size_t value)
{
	try
	{
		size_t k_size = value / 1024;
		size_t m_size = k_size / 1024;
		size_t g_size = m_size / 1024;
		size_t t_size = g_size / 1024;

		stringstream ss;

		ss << showbase << hex;

		if (t_size != 0)
			ss << setw(6) << t_size << " T ";

		if (g_size != 0)
			ss << setw(6) << g_size - t_size * 1024 << " G ";

		if (m_size != 0)
			ss << setw(6) << m_size - g_size * 1024 << " M ";

		if (k_size != 0)
			ss << setw(6) << k_size - m_size * 1024 << " K ";

		ss << value - k_size * 1024;

		ss << endl;
		ss << noshowbase << dec;

		if (t_size != 0)
			ss << setw(6) << t_size << " T ";

		if (g_size != 0)
			ss << setw(6) << g_size - t_size * 1024 << " G ";

		if (m_size != 0)
			ss << setw(6) << m_size - g_size * 1024 << " M ";

		if (k_size != 0)
			ss << setw(6) << k_size - m_size * 1024 << " K ";

		ss << value - k_size * 1024;

		ss << endl;

		Out(ss.str().c_str());
	}
	FILTER_CATCH;
}

void CTokenExt::dump_va_regions()
{
	static vector<const char*> va_region_names{
		"Non-Paged Pool",
		"Paged Pool",
		"System Cache",
		"Process Address Space(Stack)",
		"",
		"PFN Database",
		"",
		"",
		"Page Tables",
		"",		
		"",
		"",
		"",
		"",
		""
	};

	try
	{
		size_t mi_state_addr = getSymbolAddr("nt!MiState");
		ExtRemoteTyped mi_state("(nt!_MI_SYSTEM_INFORMATION*)@$extin", mi_state_addr);

		auto va_arr = mi_state_addr;
		va_arr += mi_state.GetFieldOffset("Vs.SystemVaRegions");

		uint8_t arr_raw[0x150] = { 0, };
		size_t bytes_read = 0;
		m_Data->ReadVirtual(va_arr, arr_raw, 0x150, (PULONG)&bytes_read);

		stringstream ss;
		for (size_t i = 0; i < 15; i++)
		{
			size_t addr = *(size_t*)(arr_raw + 0x10 * i);
			size_t len = *(size_t*)(arr_raw + 0x10 * i + 0x08);

			ss << setw(30) << va_region_names[i] << " [ "
				<< showbase << hex
				<< setw(18) << addr << " , "
				<< setw(18) << len << "]\n";
		}

		Out(ss.str().c_str());
	}
	FILTER_CATCH;
}


void CTokenExt::pte(size_t addr)
{
    try
    {
        stringstream ss;

        ss << "!pte " << hex << showbase << addr;
        x(ss.str().c_str());


    }
    FILTER_CATCH;
}


void CTokenExt::dump_regs()
{
	static vector<const char*> regs_name{
		"rip", "rsp",
		"rax", "rbx", "rcx", "rdx",
		"rbp", "rsi", "rdi",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
	};

	try
	{
		stringstream ss;
		for (auto& reg_entry : regs_name)
		{
			size_t reg_value = reg_of(reg_entry);
			ss.str("");
			ss << "                " << reg_entry << ": \t" << hex << showbase << setw(18) << reg_value << " ";
			Out(ss.str().c_str());
			analyze_qword(reg_value);
		}
	}
	FILTER_CATCH;
}

void CTokenExt::dump_args()
{
	try
	{
		size_t rcx = reg(REG_RCX);
		size_t rdx = reg(REG_RDX);
		size_t r8 = reg(REG_R8);
		size_t r9 = reg(REG_R9);

		size_t rsp = reg(REG_RSP);

		stringstream ss;

		ss << "                rcx: \t" << hex << showbase << setw(18) << rcx << " ";
		Out(ss.str().c_str());
		analyze_qword(rcx);

		ss.str("");
		ss << "                rdx: \t" << hex << showbase << setw(18) << rdx << " ";
		Out(ss.str().c_str());
		analyze_qword(rdx);

		ss.str("");
		ss << "                 r8: \t" << hex << showbase << setw(18) << r8 << " ";
		Out(ss.str().c_str());
		analyze_qword(r8);

		ss.str("");
		ss << "                 r9: \t" << hex << showbase << setw(18) << r9 << " ";
		Out(ss.str().c_str());
		analyze_qword(r9);

		Out("------------------------------ [ stacks : 0x%I64x ] --------------------------------\n", rsp);
		analyze_mem(rsp, 0x80);
	}
	FILTER_CATCH;
}

void CTokenExt::analyze_qword(size_t value)
{
	try
	{
		stringstream ss;

		//ss << "Analyze Qword : " << hex << showbase << value << endl;

		if (like_kaddr(value))
		{
			size_t curr_qword = value;

			if (in_curr_stack(curr_qword))
			{
				ss << setw(18) << "[ stack ] " << "rsp+" << showbase << hex << (curr_qword - reg(REG_RSP)) << ": "
					<< "\t<link cmd=\"db " << value << "\">db</link>"
					<< "\t<link cmd=\"dq " << value << "\">dq</link>"
					<< "\t<link cmd=\"dps " << value << "\">dps</link>"
					<< endl;
			}
			else
			{
				bool is_paged_pool = in_paged_pool(curr_qword);
				bool is_nonpaged_pool = in_non_paged_pool(curr_qword);

				bool is_small_pool = in_small_pool_page(curr_qword);

				if (is_paged_pool || is_nonpaged_pool)
				{
					auto pool_entry = is_small_pool ? as_small_pool(curr_qword) : as_large_pool(curr_qword);

					if (get<4>(pool_entry) == 0 && get<3>(pool_entry) == 0)
					{
						ss << setw(18) << " [ unusual pool ] " << (is_paged_pool ? " paged " : " non-paged ")
							<< showbase << hex << "<link cmd=\"!pool " << curr_qword << "\"> try !pool</link>" << endl;
					}
					else
					{
						ss << setw(18) << " [ pool ] "
							<< "      <link cmd=\"!pooltag " << get<5>(pool_entry) << ";\">" << setw(4) << get<5>(pool_entry) << "</link>\t\t"
							<< "<link cmd=\"!dk as_mem " << hex << showbase << get<3>(pool_entry) << " " << get<4>(pool_entry) << ";\">["
							<< get<3>(pool_entry) << ",  "
							<< setw(10) << (curr_qword - get<3>(pool_entry)) << " / "
							<< setw(10) << get<4>(pool_entry) << "]</link>\t\t";

						if (get<0>(pool_entry))
							ss << "Small | ";
						else
							ss << "Large | ";

						if (get<1>(pool_entry))
							ss << "Paged | ";
						else
							ss << "Non-Paged | ";

						if (get<2>(pool_entry))
							ss << "Allocated";
						else
							ss << "Free";

						ss << endl;
					}
				}
				else
				{
					auto code_details = as_kcode(curr_qword);

					if (get<0>(code_details))
					{
						ss << setw(18) << " [ code ] ";

						ss << hex << showbase << "\t<link cmd=\"u " << curr_qword << ";\">disasm</link>\t";

						if (get<3>(code_details).empty())
							ss << get<2>(code_details) << ":" << (curr_qword - get<1>(code_details)) << endl;
						else
							ss << get<3>(code_details) << endl;
					}
					else
					{
						size_t pxe_index = (curr_qword >> 39) & 0x1FF;
						size_t ppe_index = (curr_qword >> 30) & 0x1FF;
						size_t pde_index = (curr_qword >> 21) & 0x1FF;
						size_t pte_index = (curr_qword >> 12) & 0x1FF;
						size_t offset = curr_qword & 0xFFF;

						size_t cr3 = get_cr3();

						PTE64 pxe(readX<size_t>(cr3 + pxe_index * 8));
						PTE64 ppe(pxe.valid() ? readX<size_t>(pxe.PFN() + ppe_index * 8) : 0);
						PTE64 pde(ppe.valid() ? readX<size_t>(ppe.PFN() + pde_index * 8) : 0);
						PTE64 pte(pde.valid() ? readX<size_t>(pde.PFN() + pte_index * 8) : 0);

						size_t paddr = pte.PFN();

						bool b_valid_page = pxe.valid() && ppe.valid() && pde.valid() && pte.valid();

						if (b_valid_page)
						{
							ss << hex << showbase 
								<< setw(18) << " [ valid page ] "
								<< " paddr: <link cmd=\"!db " << paddr << "\">" << setw(18) << paddr << "</link>\t"
								<< pte.str() << endl;
						}
						else
							ss << setw(18) << " [ invalid page] " << endl;
					}
				}
			}

			Dml(ss.str().c_str());
		}
		else
		{
			size_t curr_qword = value;

			{				
				string raw((char*)&curr_qword, 8);
				for (char& ch : raw)
				{
					if (is_in_range<char>(ch, 'A', 'Z') || is_in_range<char>(ch, 'a', 'z') || is_in_range<char>(ch, '0', '9'))
					{
					}
					else
					{
						ch = '.';
					}
				}

				ss << setw(18) << " [     ] "
					<< hex << noshowbase << setfill('0')
					<< "[ " << setw(8) << (curr_qword & 0xFFFFFFFF) << " " << setw(8) << ((curr_qword >> 0x20) & 0xFFFFFFFF) << " ]\t"
					<< "[ " << setw(2) << ((curr_qword >> 0) & 0xFF) << " " << setw(2) << ((curr_qword >> 8) & 0xFF)
					<< " " << setw(2) << ((curr_qword >> 16) & 0xFF) << " " << setw(2) << ((curr_qword >> 24) & 0xFF)
					<< " " << setw(2) << ((curr_qword >> 32) & 0xFF) << " " << setw(2) << ((curr_qword >> 40) & 0xFF)
					<< " " << setw(2) << ((curr_qword >> 48) & 0xFF) << " " << setw(2) << ((curr_qword >> 56) & 0xFF)
					<< " |" << raw << "| "
					<< " ]" << setfill(' ')
					<< endl;
			}

			Dml(ss.str().c_str());
		}
	}
	FILTER_CATCH;
}

void CTokenExt::analyze_mem(size_t start, size_t len)
{
	try
	{
		uint8_t* buffer = new uint8_t[len];

		size_t bytes_read = 0;
		m_Data->ReadVirtual(start, buffer, len, (PULONG)&bytes_read);

		stringstream ss;

		for (size_t i = 0; i < len / 8; i++)
		{
			ss.str("");
			size_t curr_qword = *(size_t*)(buffer + i*8);

			ss << hex << showbase << "+" << setw(18) << i * 8 << ": \t" << setw(18) << curr_qword << " ";
			if (!like_kaddr(curr_qword))
			{	
				string raw((char*)&curr_qword, 8);
				for (char& ch : raw)
				{
					if (is_in_range<char>(ch, 'A', 'Z') || is_in_range<char>(ch, 'a', 'z') || is_in_range<char>(ch, '0', '9'))
					{
					}
					else
					{
						ch = '.';
					}
				}

				ss << setw(18) << " [     ] " 
				 << hex << noshowbase << setfill('0')
				 << "[ " << setw(8) << (curr_qword & 0xFFFFFFFF) << " " << setw(8) << ((curr_qword >> 0x20) & 0xFFFFFFFF) << " ]\t"
				 << "[ " << setw(2) << ((curr_qword >> 0) & 0xFF) << " " << setw(2) << ((curr_qword >> 8) & 0xFF) 
				 << " " << setw(2) << ((curr_qword >> 16) & 0xFF) << " " << setw(2) << ((curr_qword >> 24) & 0xFF)
				 <<	" " << setw(2) << ((curr_qword >> 32) & 0xFF) << " " << setw(2) << ((curr_qword >> 40) & 0xFF)
				 << " " << setw(2) << ((curr_qword >> 48) & 0xFF) << " " << setw(2) << ((curr_qword >> 56) & 0xFF) 
				 << " |" << raw << "| "
				 << " ]" << setfill(' ')
				 << endl;

				Dml(ss.str().c_str());
			}
			else if (curr_qword >= start && curr_qword < start + len)
			{
				ss << setw(18) << " [ local ] ";

				if (curr_qword == (start + i * 8))
				{
					size_t next_qword = *(size_t*)(buffer + i * 8 + 8);

					if (next_qword == curr_qword)
					{
						ss << " _LIST_ENTRY.Flink" << endl;

						ss << hex << showbase << "+" << setw(18) << i * 8 << ": \t" << setw(18) << curr_qword << " "
							<< setw(18) << " [ local ] " << " _LIST_ENTRY.Blink" << endl;

						i++;
					}
					else
					{
						ss << " Self-Pointing " << (curr_qword - start) << endl;
					}
				}
				else
				{
					ss << " Pointing to " << (curr_qword - start) << endl;
				}

				Dml(ss.str().c_str());
			}
			else
			{
				Dml(ss.str().c_str());
				analyze_qword(curr_qword);
				
			}

			
		}
		
	}
	FILTER_CATCH;
}

bool CTokenExt::like_kaddr(size_t addr)
{

	if ((addr & 0xFFFF000000000000) == 0xFFFF000000000000)
	{
		if (addr == 0xffffffff00000000)
			return false;

		if (addr == 0xffffffffffffffff)
			return false;

		if ((addr & 0xffffffff) < 0x1000)
			return false;

		
		return true;
	}

	return false;
}

bool CTokenExt::in_user_heap(size_t addr)
{
	if ((addr & 0xFFFF000000000000) == 0xFFFF000000000000)
		return false;

	if (addr < 0x800000)
		return false;

	try
	{
		size_t proc_addr = curr_proc();

		ExtRemoteTyped eproc("(nt!_EPROCESS*)@$extin", proc_addr);
		auto peb = eproc.Field("Peb");

		size_t heap_count = peb.Field("NumberOfHeaps").GetUlong();
		size_t heaps = peb.Field("ProcessHeaps").GetUlongPtr();

		for (size_t i = 0; i < heap_count; i++)
		{
			size_t heap_addr = read<size_t>(heaps + i * 8);

			ExtRemoteTyped heap("(nt!_HEAP*)@$extin", heap_addr);

			size_t heap_segment_list_head = heap.GetFieldOffset("SegmentList") + heap_addr;

			size_t curr_segment_entry = read<size_t>(heap_segment_list_head);
			while (curr_segment_entry != heap_segment_list_head)
			{ 
				ExtRemoteTyped heap_segment("(nt!_HEAP_SEGMENT*)@$extin", curr_segment_entry - 0x18);

				size_t segment_start = heap_segment.Field("BaseAddress").GetUlongPtr();
				size_t segment_end = heap_segment.Field("LastValidEntry").GetUlongPtr();

				if (addr >= segment_start && addr < segment_end)
					return true;

				curr_segment_entry = read<size_t>(curr_segment_entry);
			};
		}
	}
	FILTER_CATCH;

	return false;
}

bool CTokenExt::in_curr_stack(size_t addr)
{
	size_t rsp = reg(REG_RSP);

	return (addr ^ rsp) < 0x4000;
}

bool CTokenExt::in_paged_pool(size_t addr)
{
	static size_t page_pool_start = 0;

	try
	{
		if (page_pool_start == 0)
		{
			size_t mi_state_addr = getSymbolAddr("nt!MiState");
			ExtRemoteTyped mi_state("(nt!_MI_SYSTEM_INFORMATION*)@$extin", mi_state_addr);

			auto va_arr = mi_state_addr;
			va_arr += mi_state.GetFieldOffset("Vs.SystemVaRegions");

			size_t bytes_read = 0;
			m_Data->ReadVirtual(va_arr + 0x10, &page_pool_start, 0x8, (PULONG)&bytes_read);

			
		}

		return (addr ^ page_pool_start) < 0x1000000000;
		
	}FILTER_CATCH;

	return false;
}

bool CTokenExt::in_non_paged_pool(size_t addr)
{
	static size_t non_page_pool_start = 0;

	try
	{
		if (non_page_pool_start == 0)
		{
			size_t mi_state_addr = getSymbolAddr("nt!MiState");
			ExtRemoteTyped mi_state("(nt!_MI_SYSTEM_INFORMATION*)@$extin", mi_state_addr);

			auto va_arr = mi_state_addr;
			va_arr += mi_state.GetFieldOffset("Vs.SystemVaRegions");

			size_t bytes_read = 0;
			m_Data->ReadVirtual(va_arr, &non_page_pool_start, 0x8, (PULONG)&bytes_read);

					
		}

		return (addr ^ non_page_pool_start) < 0x1000000000;
	}FILTER_CATCH;

	return false;
}

bool CTokenExt::in_small_pool_page(size_t addr)
{
	try
	{
		size_t page_start_addr = addr & 0xFFFFFFFFFFFFF000;

		uint8_t fields[8] = { 0, };

		size_t bytes_read = 0;
		m_Data->ReadVirtual(page_start_addr, fields, 8, (PULONG)&bytes_read);

		bool b_valid_pool_page = (fields[2] != 0 && is_alpha(fields[4]) && fields[0] == 0);

		return b_valid_pool_page;
	}
	FILTER_CATCH;

	return false;
}

tuple<bool, size_t, string, string> CTokenExt::as_kcode(size_t addr)
{
	if ((addr & 0xFFFF000000000000) == 0xFFFF000000000000)
	{
		try
		{
			ExtRemoteTypedList lm_list = ExtNtOsInformation::GetKernelLoadedModuleList();

			{
				for (lm_list.StartHead(); lm_list.HasNode(); lm_list.Next())
				{
					ExtRemoteTyped lm = lm_list.GetTypedNode();
					size_t name_addr = lm_list.GetNodeOffset() + lm.GetFieldOffset("FullDllName");
					size_t dll_base = lm.Field("DllBase").GetUlong64();
					size_t dll_len = lm.Field("SizeOfImage").GetUlong();

					wstring module_name = readUnicodeString(name_addr);
					string str_module_name(module_name.size(), ' ');

					transform(module_name.begin(), module_name.end(), str_module_name.begin(), [](wchar_t wch) { return wch & 0xFF; });

					string symbol = getAddrSymbol(addr);

					size_t symbol_start = getSymbolAddr(symbol.c_str());

					stringstream ss;
					ss << symbol;

					if (addr != symbol_start)
						ss << "+" << hex << showbase << (addr - symbol_start);

					if (addr >= dll_base && addr < dll_base + dll_len)
						return make_tuple(true, dll_base, str_module_name, ss.str());
				}
			}
		}
		FILTER_CATCH;
	}

	return make_tuple(false, 0, "", "");
}

tuple<bool, size_t, string, string> CTokenExt::as_ucode(size_t addr)
{
	if ((addr & 0xFFFF000000000000) == 0x0000000000000000)
	{
		try
		{
			ExtRemoteTypedList lm_list = ExtNtOsInformation::GetUserLoadedModuleList();

			{
				for (lm_list.StartHead(); lm_list.HasNode(); lm_list.Next())
				{
					ExtRemoteTyped lm = lm_list.GetTypedNode();
					size_t name_addr = lm_list.GetNodeOffset() + lm.GetFieldOffset("FullDllName");
					size_t dll_base = lm.Field("DllBase").GetUlong64();
					size_t dll_len = lm.Field("SizeOfImage").GetUlong();

					wstring module_name = readUnicodeString(name_addr);
					string str_module_name(module_name.size(), ' ');

					transform(module_name.begin(), module_name.end(), str_module_name.begin(), [](wchar_t wch) { return wch & 0xFF; });

					string symbol = getAddrSymbol(addr);

					size_t symbol_start = getSymbolAddr(symbol.c_str());

					stringstream ss;
					ss << symbol;

					if (addr != symbol_start)
						ss << "+" << hex << showbase << (addr - symbol_start);

					if (addr >= dll_base && addr < dll_base + dll_len)
						return make_tuple(true, dll_base, str_module_name, ss.str());
				}
			}
		}
		FILTER_CATCH;
	}

	return make_tuple(false, 0, "", "");
}

tuple<bool, bool, bool, size_t, size_t, string> CTokenExt::as_small_pool(size_t addr)
{
	try 
	{
		size_t page_start_addr = addr & 0xFFFFFFFFFFFFF000;

		size_t next_record = page_start_addr;
		while (next_record >= page_start_addr && next_record < page_start_addr + 0x1000)
		{
			CPoolHeader pool_header(read<size_t>(next_record));
						
			string str_tag((char*)pool_header.tag, 4);

			if (addr >= next_record && addr < next_record + pool_header.block_size * 0x10)
			{
				bool b_Paged_or_nonpaged = ((pool_header.pool_type & 1) == 1);
				bool b_Allocated_or_free = !((pool_header.block_size == 0) || (str_tag == "Free"));

				return make_tuple(true, b_Paged_or_nonpaged, b_Allocated_or_free, next_record + 0x10, pool_header.block_size * 0x10 - 0x10, str_tag);
			}
			
			next_record += pool_header.block_size * 0x10;
		};
	}
	FILTER_CATCH;

	return make_tuple(false, false, false, 0, 0, "");
}

tuple<bool, bool, bool, size_t, size_t, string> CTokenExt::as_large_pool(size_t addr)
{
	uint8_t* page_x3_buffer = new uint8_t[0x3000];

	try
	{
		size_t big_pool_addr = read<size_t>(getSymbolAddr("nt!PoolBigPageTable"));
		size_t big_pool_size = read<size_t>(getSymbolAddr("nt!PoolBigPageTableSize"));

		stringstream ss;

		size_t item_count = 0;
		size_t page_x3_index = 0;

		for (size_t item_addr = big_pool_addr; item_count < big_pool_size; item_addr += 0x18)
		{
			if ((item_count % 0x200) == 0)
			{
				size_t bytes_read = 0;
				m_Data->ReadVirtual(big_pool_addr + page_x3_index * 0x3000, page_x3_buffer, 0x3000, (PULONG)&bytes_read);

				page_x3_index++;
			}

			item_count++;

			CBigPoolHeader pool_entry(page_x3_buffer + 0x18 * (item_count % 0x200));

			size_t pool_va = pool_entry.va & 0xFFFFFFFFFFFFF000;

			if (pool_va != pool_entry.va)
				continue;

			if (like_kaddr(pool_entry.va))
			{
				if ((addr >= pool_va) && (addr < (pool_va + pool_entry.size)))
				{
					bool b_free = ((pool_entry.va & 0x1) == 0x1);

					bool b_Paged_or_nonpaged = ((pool_entry.pool_type & 1) == 1);
					string pool_tag = pool_entry.tag;
					bool b_Allocated_or_free = !(b_free || (pool_entry.size == 0) || (pool_tag == "Free"));

					delete[] page_x3_buffer;
					return make_tuple(false, b_Paged_or_nonpaged, b_Allocated_or_free, pool_va, pool_entry.size, pool_tag);
				}
			}
		}
	}
	FILTER_CATCH;

	delete[] page_x3_buffer;

	return make_tuple(false, false, false, 0, 0, "");
}

void CTokenExt::dump_token_buffer(size_t addr)
{
    try
    {
        stringstream ss;

        ExtRemoteTyped token("(nt!_EPROCESS*)@$extin", addr);
        size_t variable_part = token.Field("VariablePart").GetUlongPtr();

        size_t len = variable_part - addr;

        ss << hex << showbase
            << "db " << addr << " L" << len;

        x(ss.str());
    }
    FILTER_CATCH;
}

bool CTokenExt::is_reg(string & str)
{
    static vector<string> regs{ {
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16"
        } };

    return find(regs.begin(), regs.end(), str.c_str()) != regs.end();
}


void CTokenExt::dk(void)
{
    if (!check())
        return;

    try
    {
        string raw_args = GetRawArgStr();
        vector<string> args;
        for (size_t i = 0, j = 0; i <= raw_args.size(); i++)
        {
            if (raw_args[i] == ' ' || i == raw_args.size())
            {
                if (i > j)
                    args.push_back(string(raw_args, j, i - j));

                j = i+1;
            }                
        }

        if (!args.empty())
        {
            string cmd = args[0];

            if (cmd == "handles")
            {
                size_t proc_addr = getIntArg(args, 1, curr_proc());
                dump_process_handle_table(proc_addr);
            }
            else if (cmd == "pses")
            {
                pses();
            }
            else if (cmd == "dbgdata")
            {
                dbgdata();
            }
            else if (cmd == "gobj")
            {
                gobj();
            }
            else if (cmd == "lmu")
            {
                lmu();
            }
            else if (cmd == "lmk")
            {
                lmk();
            }
			else if (cmd == "obj_dir")
			{
				size_t addr = getIntArg(args, 1, 0);
				dump_obj_dir(addr, 0, true);
			}
            else if (cmd == "types")
            {
                types();
            }
			else if (cmd == "ps_flags")
			{
				size_t addr = getIntArg(args, 1, 0);
				dump_ps_flags(addr);
			}
            else if (cmd == "threads")
            {
                size_t proc_addr = getIntArg(args, 1, 0);
                dump_process_threads(proc_addr);
            }
			else if (cmd == "size")
			{
				size_t value = getIntArg(args, 1, 0);
				dump_size(value);
			}
			else if (cmd == "va_regions")
			{
				dump_va_regions();
			}
			else if (cmd == "regs")
			{
				dump_regs();
			}
			else if (cmd == "as_qword")
			{
				size_t value = getIntArg(args, 1, 0);
				analyze_qword(value);
			}
			else if (cmd == "as_mem")
			{
				size_t addr = getIntArg(args, 1, 0);
				size_t len = getIntArg(args, 2, 0);

				analyze_mem(addr, len);
			}
			else if (cmd == "args")
			{
				dump_args();
			}
            else if (cmd == "pool_handles")
            {
                size_t table_addr = getIntArg(args, 1, 0);
                size_t count = getIntArg(args, 2, 0);
                dump_pool_handles(table_addr, count);
            }
			else if (cmd == "pool")
			{
				size_t addr = getIntArg(args, 1, 0);
				analyze_qword(addr);
			}
            else if (cmd == "sessions")
            {
                dump_logon_sessions();
            }
            else if (cmd == "obj")
            {
                size_t obj_addr = getIntArg(args, 1, 0);
                dump_obj(obj_addr);
            }
            else if (cmd == "process")
            {
                size_t proc_addr = getIntArg(args, 1, curr_proc());
                dump_process(proc_addr);
            }
            else if (cmd == "handle_table")
            {
                size_t handle_table_addr = getIntArg(args, 1, 0);
                dump_handle_table(handle_table_addr);
            }
            else if (cmd == "khandles")
            {
                dump_kernel_handle_table();
            }
            else if (cmd == "sdr")
            {
                size_t sdr_addr = getIntArg(args, 1, 0) & 0xFFFFFFFFFFFFFFF0;
                dump_sdr(sdr_addr);
            }
            else if (cmd == "token")
            {
                size_t token_addr = getIntArg(args, 1, curr_token());
                dump_token(token_addr);
            }
            else if (cmd == "kill")
            {
                size_t proc_addr = getIntArg(args, 1, curr_proc());
                kill_process(proc_addr);
            }
            else if (cmd == "add_privilege")
            {
                size_t privilege_mask = getIntArg(args, 1, 0xFFFFFFFFC);
                size_t token_addr = getIntArg(args, 2, curr_token());
                token_privilege_add(token_addr, privilege_mask);
            }
            else if (cmd == "sid")
            {
                size_t sid_addr = getIntArg(args, 1, 0);
                Out("Sid(0x%0I64x) : %s\n", sid_addr, dump_sid(sid_addr).c_str());
            }
            else if (cmd == "acl")
            {
                size_t acl_addr = getIntArg(args, 1, 0);
                Out("Acl(0x%0I64x) : %s\n", acl_addr, dump_acl(acl_addr).c_str());
            }
			else if (cmd == "page")
			{
				size_t addr = getIntArg(args, 1, 0);
				dump_page_info(addr);
			}
			else if (cmd == "pages")
			{
				size_t addr = getIntArg(args, 1, 0);
				dump_pages_around(addr);
			}
            else if (cmd == "hole")
            {
                size_t rsp_addr = getIntArg(args, 1, 0);
                dump_hole(rsp_addr);
            }
            else if (cmd == "free_pool")
            {
                size_t size = getIntArg(args, 1, 0);
                dump_free_pool(size);
            }
            else if (cmd == "kall")
            {
                dump_threads_stack(curr_proc());
            }
            else if (cmd == "pkall")
            {
                dump_all_threads_stack();
            }
            else if (cmd == "lm")
            {
                dump_modules();
            }
            else if (cmd == "bigpool")
            {
                dump_big_pool();
            }
            else if (cmd == "poolrange")
            {
                dump_pool_range();
            }
            else if (cmd == "pooltrack")
            {
                dump_pool_track();
            }
            else if (cmd == "poolmetrics")
            {
                dump_pool_metrics();
            }
            else if (cmd == "link")
            {
                size_t addr = getIntArg(args, 1, 0);
                dig_link(addr);
            }
            else if (cmd == "tpool")
            {
                size_t addr = getIntArg(args, 1, 0);
                tpool(addr);
            }
            else if (cmd == "poolhdr")
            {
                size_t addr = getIntArg(args, 1, 0);
                poolhdr(addr);
            }
            else if (cmd == "sessionpool")
            {
                dump_session_pool();
            }
            else if (cmd == "peguid")
            {
                size_t addr = getIntArg(args, 1, 0);
                dump_pe_guid(addr);
            }
            else if (cmd == "memcpy")
            {
                size_t src_addr = getIntArg(args, 1, 0);
                size_t dst_addr = getIntArg(args, 2, 0);
                size_t count = getIntArg(args, 3, 0);
                do_memcpy(src_addr, dst_addr, count);
            }
            else
            {
                Err("Unsupported dk commands!\n");
                dump_usage();
            }
        }
        else
        {
            Err("Invalid parameters\n");
        }
    }
    FILTER_CATCH
}

void CTokenExt::dump_user_modules()
{
    ExtRemoteTypedList lm_list = ExtNtOsInformation::GetUserLoadedModuleList();

    for (lm_list.StartHead(); lm_list.HasNode(); lm_list.Next())
    {
        ExtRemoteTyped lm = lm_list.GetTypedNode();
        size_t name_addr = lm_list.GetNodeOffset() + lm.GetFieldOffset("FullDllName");
        size_t dll_base = lm.Field("DllBase").GetUlong64();
        Out(L"0x%0I64x %s\n", dll_base, readUnicodeString(name_addr).c_str());
    }
}

void CTokenExt::dump_kernel_modules()
{

    ExtRemoteTypedList klm_list = ExtNtOsInformation::GetKernelLoadedModuleList();

    for (klm_list.StartHead(); klm_list.HasNode(); klm_list.Next())
    {
        ExtRemoteTyped lm = klm_list.GetTypedNode();
        size_t name_addr = klm_list.GetNodeOffset() + lm.GetFieldOffset("FullDllName");
        size_t dll_base = lm.Field("DllBase").GetUlong64();
        Out(L"0x%0I64x %s\n", dll_base, readUnicodeString(name_addr).c_str());
    }
} 

CTokenExt::~CTokenExt()
{
} 

wstring CTokenExt::getTypeName(size_t index)
{ 
    if (m_type_name_map.find(index) == m_type_name_map.end())
    {
        size_t type_entry_addr = 0;
        if (S_OK == m_Data->ReadVirtual(m_type_index_table_addr + index * 0x08, &type_entry_addr, sizeof(size_t), NULL))
        {
            ExtRemoteTyped ob_type_entry("(nt!_OBJECT_TYPE*)@$extin", type_entry_addr);
            m_type_name_map[index] = readUnicodeString(type_entry_addr + ob_type_entry.GetFieldOffset("Name"));
        }
    }

    if (m_type_name_map.find(index) != m_type_name_map.end())
        return m_type_name_map[index];

    return L"";
} 

uint8_t CTokenExt::realIndex(size_t type_index, size_t obj_hdr_addr)
{
    uint8_t byte_2nd_addr = obj_hdr_addr >> 8;
    return type_index ^ m_ob_header_cookie ^ byte_2nd_addr;
}

void CTokenExt::handles(void)
{
    if (!check())
        return;

    auto param1 = GetUnnamedArgU64(0);
    if (0 == param1)
        m_System->GetCurrentProcessDataOffset(&param1);

    dump_kernel_handle_table();
    //dump_process_handle_table(param1);     
} 

size_t CTokenExt::readDbgDataAddr(ULONG index)
{
    size_t addr_field = 0;
    m_Data->ReadDebuggerData(index, &addr_field, sizeof(size_t), NULL);
    return addr_field;
}

void CTokenExt::dump_obj(size_t obj_addr, bool b_simple)
{
    try
    {
        ExtRemoteTyped obj_hdr("(nt!_OBJECT_HEADER*)@$extin", obj_addr);
        //obj_hdr.OutFullValue();

        uint8_t real_index = realIndex(obj_hdr.Field("TypeIndex").GetUchar(), obj_addr);
        size_t sdr_addr = obj_hdr.Field("SecurityDescriptor").GetLongPtr() & 0xFFFFFFFFFFFFFFF0;

		wstring obj_name = dump_obj_name(obj_addr);
		wstring type_name = getTypeName(real_index);

		string str_type_name(type_name.size(), ' ');
		string str_obj_name(obj_name.size(), ' ');

		transform(obj_name.begin(), obj_name.end(), str_obj_name.begin(), [](wchar_t wch) { return wch & 0xFF; });
		transform(type_name.begin(), type_name.end(), str_type_name.begin(), [](wchar_t wch) { return wch & 0xFF; });

		stringstream ss;

		ss << hex << showbase;

		ss << "<link cmd=\"!object ";

		ss << obj_addr + 0x30 << "\">" << setw(18) << obj_addr << "</link> "
			<< setw(20) << str_type_name << " [" << setw(4) << (uint16_t)real_index << "]   ";

		if (obj_name.empty() && type_name == L"File")
		{
			wstring file_name = dump_file_name(obj_addr + 0x30);
			string str_file_name(file_name.size(), ' ');

			transform(file_name.begin(), file_name.end(), str_file_name.begin(), [](wchar_t wch) { return wch & 0xFF; });

			ss << str_file_name;
		}
		else
			ss << str_obj_name;

		ss << endl;

		if (!b_simple)
		{

			uint8_t info_mask = obj_hdr.Field("InfoMask").GetUchar();

			size_t mask2off_table_addr = getSymbolAddr("nt!ObpInfoMaskToOffset");
			uint8_t offset = read<uint8_t>(mask2off_table_addr + info_mask);

			size_t opt_hdr_start = obj_addr - offset;

			if (info_mask & 0x10)
			{
				ExtRemoteTyped ob_opt_info("(nt!_OBJECT_HEADER_PROCESS_INFO*)@$extin", opt_hdr_start);

				ss << string(25, '-') << setw(30) << "[ process info : "
					<< hex << showbase
					<< "<link cmd =\"dt nt!_OBJECT_HEADER_PROCESS_INFO "
					<< opt_hdr_start
					<< "\">"
					<< opt_hdr_start
					<< "</link>"
					<< " ]" << string(25, '-') << endl;

				size_t proc_addr = ob_opt_info.Field("ExclusiveProcess").GetUlongPtr();

				ss << "Process: <link cmd=\"!dk process " << proc_addr << "\">" << proc_addr << "</link>" << endl;

				opt_hdr_start += 0x10;
			}

			if (info_mask & 0x08)
			{
				ExtRemoteTyped ob_opt_info("(nt!_OBJECT_HEADER_QUOTA_INFO*)@$extin", opt_hdr_start);

				ss << string(25, '-') << setw(30) << "[ quota info : "
					<< hex << showbase
					<< "<link cmd =\"dt nt!_OBJECT_HEADER_QUOTA_INFO "
					<< opt_hdr_start
					<< "\">"
					<< opt_hdr_start
					<< "</link>"
					<< " ]" << string(25, '-') << endl;

				uint32_t page_charge = ob_opt_info.Field("PagedPoolCharge").GetUlong();
				uint32_t npage_charge = ob_opt_info.Field("NonPagedPoolCharge").GetUlong();
				uint32_t sd_charge = ob_opt_info.Field("SecurityDescriptorCharge").GetUlong();

				ss << setw(40) << "Paged Pool Charge: " << page_charge << endl
					<< setw(40) << "Non-Paged Pool Charge: " << npage_charge << endl
					<< setw(40) << "Security Descrptor Charge: " << sd_charge << endl;

				opt_hdr_start += 0x20;
			}

			if (info_mask & 0x04)
			{
				ExtRemoteTyped ob_opt_info("(nt!_OBJECT_HEADER_HANDLE_INFO*)@$extin", opt_hdr_start);

				ss << string(25, '-') << setw(30) << "[ handle info : "
					<< hex << showbase
					<< "<link cmd =\"dt nt!_OBJECT_HEADER_HANDLE_INFO "
					<< opt_hdr_start
					<< "\">"
					<< opt_hdr_start
					<< "</link>"
					<< " ]" << string(25, '-') << endl;

				opt_hdr_start += 0x10;
			}

			if (info_mask & 0x02)
			{
				ExtRemoteTyped ob_opt_info("(nt!_OBJECT_HEADER_NAME_INFO*)@$extin", opt_hdr_start);
				wstring obj_name = readUnicodeString(obj_addr - offset + ob_opt_info.GetFieldOffset("Name"));

				wstring type_name = getTypeName(realIndex(obj_hdr.Field("TypeIndex").GetUchar(), obj_addr));
				if (type_name == L"SymbolicLink")
				{
					obj_name += L" --> ";
					obj_name += dump_sym_link(obj_addr);
				}

				ss << string(25, '-') << setw(30) << "[ name info : "
					<< hex << showbase
					<< "<link cmd =\"dt nt!_OBJECT_HEADER_NAME_INFO "
					<< opt_hdr_start
					<< "\">"
					<< opt_hdr_start
					<< "</link>"
					<< " ]" << string(25, '-') << endl;

				size_t dir_addr = ob_opt_info.Field("Directory").GetUlongPtr();

				if (dir_addr != 0)
				{
					ss << "Parent Directory: <link cmd=\"dt nt!_OBJECT_DIRECTORY " << dir_addr << "\">" << dir_addr << "</link> "
						<< "\t\t<link cmd=\"!dk obj " << dir_addr - 0x30 << "\">detail</link> "
						<< "\t\t<link cmd=\"!dk obj_dir " << dir_addr << "\">listdir</link>"
						<< endl;
				}

				opt_hdr_start += 0x20;
			}

			if (info_mask & 0x01)
			{
				ExtRemoteTyped ob_opt_info("(nt!_OBJECT_HEADER_CREATOR_INFO*)@$extin", opt_hdr_start);

				ss << string(25, '-') << setw(30) << "[ creator info : "
					<< hex << showbase
					<< "<link cmd =\"dt nt!_OBJECT_HEADER_CREATOR_INFO "
					<< opt_hdr_start
					<< "\">"
					<< opt_hdr_start
					<< "</link>"
					<< " ]" << string(25, '-') << endl;

				size_t proc_addr = ob_opt_info.Field("CreatorUniqueProcess").GetUlongPtr();

				ss << "Creator: <link cmd=\"!dk process " << proc_addr << "\">" << proc_addr << "</link>" << endl;

				opt_hdr_start += 0x20;
			}

			ss << string(25, '-') << setw(30) << "[ security descriptor : "
				<< hex << showbase
				<< "<link cmd =\"dt nt!_SECURITY_DESCRIPTOR_RELATIVE "
				<< sdr_addr
				<< "\">"
				<< sdr_addr
				<< "</link>"
				<< " ]" << string(25, '-') << endl;
		}

		Dml(ss.str().c_str());

        if (!b_simple && sdr_addr != 0)
            dump_sdr(sdr_addr, wstr2str(type_name));         

    }
    FILTER_CATCH;
}

string CTokenExt::wstr2str(wstring wstr)
{
	string str(wstr.size(), ' ');

	transform(wstr.begin(), wstr.end(), str.begin(), [](wchar_t wch) { return wch & 0xFF; });

	return str;
}

void CTokenExt::dump_process(size_t process_addr)
{
    try
	{
		ExtRemoteTyped ps("(nt!_EPROCESS*)@$extin", process_addr);
		size_t name_addr = process_addr + ps.GetFieldOffset("ImageFileName");
		char name[16] = { 0, };
		m_Data->ReadVirtual(name_addr, name, 15, NULL);
		size_t pid = ps.Field("UniqueProcessId").GetUlongPtr();
		uint8_t protection = read<uint8_t>(process_addr + ps.GetFieldOffset("Protection"));
		uint8_t signing_level = read<uint8_t>(process_addr + ps.GetFieldOffset("SignatureLevel"));
		uint8_t dll_signing_level = read<uint8_t>(process_addr + ps.GetFieldOffset("SectionSignatureLevel"));
		size_t token_addr = ps.Field("Token.Object").GetUlong64();

		size_t pico_context = ps.Field("PicoContext").GetUlongPtr();
		size_t trustlet_id = ps.Field("TrustletIdentity").GetUlong64();

		uint32_t flags = ps.Field("Flags").GetUlong();
		uint32_t flags2 = ps.Field("Flags2").GetUlong();
		uint32_t flags3 = ps.Field("Flags3").GetUlong();

		bool b_minimal = ((flags3 & 0x01) == 1);

		bool b_cfg = ((flags & 0x10) == 0x10);

		size_t dir_table_base = ps.Field("Pcb.DirectoryTableBase").GetUlong64();

		string il_str = getTokenIL(token_addr & 0xFFFFFFFFFFFFFFF0).c_str();

		//Out("\tPico: 0x%I64x, Trustlet ID: 0x%I64x\t, Minimal: %s\t", pico_context, trustlet_id, b_minimal ? "T":" ");

		stringstream ss;

		ss << hex << showbase
			<< "<link cmd=\"!process " << process_addr << "\">" << process_addr << "</link> "
            << "<link cmd=\"dt nt!_EPROCESS " << process_addr << "\">dt</link> ";

		char il = ' ';
		if (!il_str.empty())
		{
			il = *(++il_str.rbegin());
		}

		if (il == '0' || il == '1' || il == '2')
			ss << "<link cmd=\".kill " << process_addr << ";g;\">kill</link> ";
		else
			ss << "     ";

		ss << "<link cmd=\"!dk handles " << process_addr << "\">handles</link> ";

        ss << "<link cmd=\"!dk obj " << process_addr - 0x30 << "\">detail</link> ";

        ss << "<link cmd=\"!dk threads " << process_addr << "\">threads</link> ";

        ss << "<link cmd=\".process /i " << process_addr << "\">switch</link> ";


		ss << setw(16) << name << " "
			<< setw(8) << noshowbase << hex << pid << "(" << dec << setw(8) << pid << ")   " << hex
			<< setw(2) << (uint16_t)protection << "(" << setw(2) << (uint16_t)signing_level << ", " << setw(2) << (uint16_t)dll_signing_level << ") "
			<< setw(16) << getProtectionText(protection) << " "
			<< setw(14) << getTokenIL(token_addr & 0xFFFFFFFFFFFFFFF0) << " "
			<< showbase << setw(12) << dir_table_base << "  "
			<< "<link cmd=\"!dk ps_flags " << showbase << hex << process_addr << "\">Flags: ["
			<< noshowbase << setw(8) << flags << ", " << setw(8) << flags2 << ", " << setw(8) << flags3 << "]</link> " << showbase;

		if (pico_context != 0)
			ss << " Pico: " << pico_context << " ";

		if (trustlet_id != 0)
			ss << " Trustlet Id: " << trustlet_id << " ";

		if (b_minimal)
			ss << " Minimal ";

		if (b_cfg)
			ss << " CFG ";

		ss << endl;


		//if (!il_str.empty())
		//{
		//    auto il = *(++il_str.rbegin());
		//    if (il == '0' || il == '1' || il == '2')
		//        Dml("<link cmd=\"!process 0x%0I64x\">0x%0I64x</link> <link cmd=\".kill 0x%0I64x;g;\">kill</link> %8x %02x(%02x, %02x) %20s %40s %50s %0I64x\n",
		//            process_addr, process_addr, process_addr, pid, protection, signing_level, dll_signing_level, name,
		//            getProtectionText(protection).c_str(),
		//            getTokenIL(token_addr & 0xFFFFFFFFFFFFFFF0).c_str(),
		//            dir_table_base);
		//    else
		//    {
		//        Dml("<link cmd=\"!process 0x%0I64x\">0x%0I64x</link>      %8x %02x(%02x, %02x) %20s %40s %50s %0I64x\n",
		//            process_addr, process_addr, pid, protection, signing_level, dll_signing_level, name,
		//            getProtectionText(protection).c_str(),
		//            getTokenIL(token_addr & 0xFFFFFFFFFFFFFFF0).c_str(),
		//            dir_table_base);
		//    }
		//}
		//else
		//{
		//    Dml("<link cmd=\"!process 0x%0I64x\">0x%0I64x</link>      %8x %02x(%02x, %02x) %20s %40s %50s %0I64x\n",
		//        process_addr, process_addr, pid, protection, signing_level, dll_signing_level, name,
		//        getProtectionText(protection).c_str(),
		//        getTokenIL(token_addr & 0xFFFFFFFFFFFFFFF0).c_str(),
		//        dir_table_base);
		//}

		Dml(ss.str().c_str());
    }
    FILTER_CATCH;
}

void CTokenExt::dump_handle_table(size_t handle_table_addr)
{
    size_t table_code = 0;
    size_t handle_count = 0;

    try
    {
        ExtRemoteTyped handle_table("(nt!_HANDLE_TABLE*)@$extin", handle_table_addr);  
        table_code = handle_table.Field("TableCode").GetLongPtr(); 
        auto free_list1 = handle_table.Field("FreeLists").ArrayElement(0);
        handle_count = free_list1.Field("HandleCount").GetUlong();
    }
    FILTER_CATCH;

    size_t level = table_code & 0x00000000000000FF;
    size_t l1_addr = table_code & 0xFFFFFFFFFFFFFF00;

    CHandleTable handle_table(level, l1_addr, handle_count);
    
    //Out("HandleTable : 0x%I64x, count: 0x%08x, level: 0x%08x\n", handle_table_addr, handle_count, level);
    //Out("%-18s %-18s %-10s %-10s %-4s %-20s %s\n", "object_table_entry", "object_header_addr", "access", "handle", "type", "type_name", "object_name");
    size_t handle_value = 0;
    handle_table.traverse([this, &handle_value](size_t entry, size_t access) {
        //static size_t handle_value = 0;
        bool bRet = false;

        if ((entry & 0x01) != 0 &&
            (entry & 0x8000000000000000) != 0)
        {
            size_t addr = ((entry >> 0x10) | 0xFFFF000000000000) & 0xFFFFFFFFFFFFFFF0;

            if (valid_addr(addr))
            {
                try
                {
                    ExtRemoteTyped obj_header("(nt!_OBJECT_HEADER*)@$extin", addr);
                    uint8_t real_index = realIndex(obj_header.Field("TypeIndex").GetUchar(), addr);

                    wstring obj_name = dump_obj_name(addr);
                    wstring type_name = getTypeName(real_index);

					string str_type_name(type_name.size(), ' ');
					string str_obj_name(obj_name.size(), ' ');

					transform(obj_name.begin(), obj_name.end(), str_obj_name.begin(), [](wchar_t wch) { return wch & 0xFF; });
					transform(type_name.begin(), type_name.end(), str_type_name.begin(), [](wchar_t wch) { return wch & 0xFF; });

					stringstream ss;
					
					ss << hex << showbase
						<< setw(18) << entry << " ";

                    ss << "<link cmd=\"!object ";

					ss << addr + 0x30 << "\">" << setw(18) << addr << "</link> "
						<< "<link cmd=\"!dk obj " << addr << "\">detail</link> "
						<< setw(10) << access << " "
						<< hex << setw(8) << handle_value << /*(" << setw(8) << dec << noshowbase << handle_value << hex << showbase << ")*/" "
						<< setw(20) << str_type_name << " [" << setw(4) << (uint16_t)real_index << "]   ";

					if (obj_name.empty() && type_name == L"File")
					{
						wstring file_name = dump_file_name(addr + 0x30);
						string str_file_name(file_name.size(), ' ');

						transform(file_name.begin(), file_name.end(), str_file_name.begin(), [](wchar_t wch) { return wch & 0xFF; });

						ss << str_file_name;
					}
					else
						ss << str_obj_name;

					ss << endl;

					Dml(ss.str().c_str());
                }
                FILTER_CATCH;
            }
            else
                Out("----> Invalid addr at 0x%0I64x\n", addr);

            bRet = true;
        }

        handle_value += 4;

        return bRet;
    });
}

void CTokenExt::dump_kernel_handle_table()
{
    try
    {
        size_t kernel_handle_table_addr = getSymbolAddr("nt!ObpKernelHandleTable");
        dump_handle_table(read<size_t>(kernel_handle_table_addr));
    }
    FILTER_CATCH
}

void CTokenExt::dump_process_handle_table(size_t process_addr)
{
    try
    {
        ExtRemoteTyped curr_eprocess("(nt!_EPROCESS*)@$extin", process_addr); 
        size_t handle_table_addr = curr_eprocess.Field("ObjectTable").GetLongPtr();
        dump_handle_table(handle_table_addr);
    }
    FILTER_CATCH
}

void CTokenExt::dump_sdr(size_t sd_addr, string type_name)
{
    try
    {
        if (0 == sd_addr)
        {
            Out("[null] SD\n");
            return;
        }

        uint16_t word_control = read<uint16_t>(sd_addr + 2);

        if (word_control & 0x8000)
        {
            ExtRemoteTyped sdr("(nt!_SECURITY_DESCRIPTOR_RELATIVE*)@$extin", sd_addr);
            //sdr.OutFullValue();

            Out("[Security Descriptor:]\n");
            uint32_t owner_off = sdr.Field("Owner").GetUlong();
            if (owner_off != 0)
                Out("--Owner: %s\n", dump_sid(sd_addr + owner_off).c_str());
            uint32_t group_off = sdr.Field("Group").GetUlong();
            if (group_off != 0)
                Out("--Group: %s\n", dump_sid(sd_addr + group_off).c_str());
            uint32_t sacl_off = sdr.Field("Sacl").GetUlong();
            if (sacl_off != 0)
                Out("--Sacl:\n%s\n", dump_acl(sd_addr + sacl_off, type_name).c_str());
            uint32_t dacl_off = sdr.Field("Dacl").GetUlong();
            if (dacl_off != 0)
                Out("--Dacl:\n%s\n", dump_acl(sd_addr + dacl_off, type_name).c_str());
        }
        else
        {
            ExtRemoteTyped sdr("(nt!_SECURITY_DESCRIPTOR*)@$extin", sd_addr);
            //sdr.OutFullValue();

            Out("[Security Descriptor:]\n");
            uint32_t owner_off = sdr.Field("Owner").GetUlong();
            if (owner_off != 0)
                Out("--Owner: %s\n", dump_sid(owner_off).c_str());
            uint32_t group_off = sdr.Field("Group").GetUlong();
            if (group_off != 0)
                Out("--Group: %s\n", dump_sid(group_off).c_str());
            uint32_t sacl_off = sdr.Field("Sacl").GetUlong();
            if (sacl_off != 0)
                Out("--Sacl:\n%s\n", dump_acl(sacl_off).c_str());
            uint32_t dacl_off = sdr.Field("Dacl").GetUlong();
            if (dacl_off != 0)
                Out("--Dacl:\n%s\n", dump_acl(dacl_off).c_str());
        }

    }
    FILTER_CATCH;
}

void CTokenExt::dump_pool_handles(size_t table_addr, size_t count)
{
    try
    {
        vector<size_t> pages;
        stringstream ss;
        size_t counter = 0;
        for (size_t i = 0; i < count; i++)
        {
            size_t pool_entry = read<size_t>(table_addr + i * 8);

            size_t page = pool_entry & 0xFFFFFFFFFFFFF000;
            
            if (find(pages.begin(), pages.end(), page) == pages.end() && pool_entry != 0)
                pages.push_back(page);
            
            if (pool_entry != 0)
            {
                ss << hex << showbase
                    << "<link cmd=\"dt nt!_BLOB " << setfill('0') << setw(16) << pool_entry - 0x30
                    << "; dt nt!_KALPC_SECTION " << setfill('0') << setw(16) << pool_entry
                    <<"\">"
                    << setfill('0') << setw(16) << pool_entry
                    << "</link>"
                    << "[<link cmd=\"!pool " << setfill('0') << setw(16) << page
                    << "\">Page " << dec << noshowbase << find(pages.begin(), pages.end(), page) - pages.begin()
                    << "</link>]\t";
            }
            else
            {
                ss << hex << showbase
                    << setfill('0') << setw(16) << pool_entry
                    << "[      ]\t";
            }


            if (i % 2 == 1)
                ss << "\n";

            if (++counter > 0x100)
            {
                Dml(ss.str().c_str());
                ss.str("");
                counter = 0;

                Dml("\n<link cmd=\"!dk pool_handles 0x%0I64x 0x%0I64x\">Continue to next 0x100 entries...</link>\n",
                    table_addr + 0x100 * 8,
                    count - 0x100);

                break;
            }
        }

        if (counter != 0)
            Dml(ss.str().c_str());

        //Dml(ss.str().c_str());
    }
    FILTER_CATCH;
}

void CTokenExt::dump_token(size_t token_addr)
{
    if (token_addr == 0)
        return;

    try
    {
        ExtRemoteTyped token("(nt!_TOKEN*)@$extin", token_addr);

        Out("Token: 0x%I64x\n", token_addr);
  
        Out("%16s: %s\n", "TokenId", dump_luid(token_addr + token.GetFieldOffset("TokenId")).c_str());
        //Out("%16s: %s\n", "AuthenticationId", dump_luid(token_addr + token.GetFieldOffset("AuthenticationId")).c_str());
        Out("%16s: %s\n", "ParentTokenId", dump_luid(token_addr + token.GetFieldOffset("ParentTokenId")).c_str());
        //Out("%16s: %s\n", "ModifiedId", dump_luid(token_addr + token.GetFieldOffset("ModifiedId")).c_str());
        Out("%16s: \n%s\n", "Privileges", dump_privilege(token_addr + token.GetFieldOffset("Privileges")).c_str());
       //Out("%16s: %s\n", "User/Groups", dump_sid_attr_array(token.Field("UserAndGroups").GetUlongPtr(), token.Field("UserAndGroupCount").GetUlong()).c_str());
       //Out("%16s: %s\n", "Restricted User/Groups", dump_sid_attr_array(token.Field("RestrictedSids").GetUlongPtr(), token.Field("RestrictedSidCount").GetUlong()).c_str());
       //Out("%16s: %s\n", "Capabilities User/Groups", dump_sid_attr_array(token.Field("Capabilities").GetUlongPtr(), token.Field("CapabilityCount").GetUlong()).c_str());
        Out("%16s: \n%s\n", "SidHash", dump_sid_attr_hash(token_addr + token.GetFieldOffset("SidHash")).c_str());
        Out("%16s: \n%s\n", "RestrictedSidHash", dump_sid_attr_hash(token_addr + token.GetFieldOffset("RestrictedSidHash")).c_str());
        Out("%16s: \n%s\n", "CapabilitiesHash", dump_sid_attr_hash(token_addr + token.GetFieldOffset("CapabilitiesHash")).c_str());
        string trust_level = dump_sid(token.Field("TrustLevelSid").GetUlongPtr());
        Out("%16s: %s [%s]\n", "TrustLevelSid", trust_level.c_str(), getTrustLabel(trust_level).c_str());

        //dump_session(token.Field("LogonSession").GetLongPtr());

        //if (m_dk_options.m_detail || m_dk_options.m_linked_token)
        //    dump_token(token.Field("TrustLinkedToken").GetUlongPtr() & 0xFFFFFFFFFFFFFFF0);
        
        //token.OutFullValue();
    }
    FILTER_CATCH;
}

void CTokenExt::dump_session(size_t session_addr)
{
    if (session_addr == 0)
        return;

    try
    {
        ExtRemoteTyped session("(nt!_SEP_LOGON_SESSION_REFERENCES*)@$extin", session_addr);
        Out("Session: 0x%I64x\n", session_addr);
        Out("%16s: %s\n", "LogonId", dump_luid(session_addr + session.GetFieldOffset("LogonId")).c_str());
        Out("%16s: %s\n", "BuddyLogonId", dump_luid(session_addr + session.GetFieldOffset("BuddyLogonId")).c_str());
        Out("%16s: 0x%I64x\n", "ReferenceCount", session.Field("ReferenceCount").GetUlong64());
        Out(L"%16s: %s\n", L"AccountName", readUnicodeString(session_addr + session.GetFieldOffset("AccountName")).c_str());
        Out(L"%16s: %s\n", L"AuthorityName", readUnicodeString(session_addr + session.GetFieldOffset("AuthorityName")).c_str());

        Out("%16s: 0x%I64x\n", "Token", session.Field("Token").GetUlongPtr());
    }
    FILTER_CATCH
}

void CTokenExt::kill_process(size_t proc_addr)
{
    try
    {
        stringstream ss;
        ss << ".kill " << hex << showbase << proc_addr << ";g;";

        x(ss.str().c_str());
    }
    FILTER_CATCH;
}

void CTokenExt::dump_logon_sessions()
{
    try
    {
        size_t logon_sessions_addr = getSymbolAddr("nt!SepLogonSessions");
        if (logon_sessions_addr == 0)
            return;

        size_t logon_sessions_table_addr = read<size_t>(logon_sessions_addr);
        if (logon_sessions_table_addr == 0)
            return;

        for (size_t i = 0; i < 0x10; i++)
        {
            size_t logon_session_addr = read<size_t>(logon_sessions_table_addr + i*8);
            if (logon_session_addr == 0)
                continue;

            Out("#%x:\n", i);
            dump_session(logon_session_addr);
        }
    }
    FILTER_CATCH;
}

void CTokenExt::token_privilege_add(size_t token_addr, size_t bitmap)
{
    try
    {
        ExtRemoteTyped token("(nt!_TOKEN*)@$extin", token_addr);
        size_t offset = token.GetFieldOffset("Privileges");
        size_t present = read<size_t>(token_addr + offset);
        present |= bitmap;
        write<size_t>(token_addr + offset, present);

        size_t enabled = read<size_t>(token_addr + offset + 8);
        enabled |= bitmap;
        write<size_t>(token_addr + offset + 8, enabled);
    }
    FILTER_CATCH
}

void CTokenExt::dump_process_threads(size_t process_addr)
{
    try
    {
        ExtRemoteTyped proc("(nt!_EPROCESS*)@$extin", process_addr);
        size_t thread_list_head_addr = process_addr + proc.GetFieldOffset("ThreadListHead");

        ExtRemoteTypedList threads_list(thread_list_head_addr, "nt!_ETHREAD", "ThreadListEntry");
		stringstream ss;
        for (threads_list.StartHead(); threads_list.HasNode(); threads_list.Next())
        {
            auto thread = threads_list.GetTypedNode();
            size_t thread_addr = threads_list.GetNodeOffset();

            size_t unique_process = thread.Field("Cid.UniqueProcess").GetUlongPtr();
            size_t unique_thread = thread.Field("Cid.UniqueThread").GetUlongPtr();

            size_t teb_addr = thread.Field("Tcb.Teb").GetUlongPtr();

            auto thread_token_info = get_thread_token(thread_addr);

            size_t thread_token_addr = get<0>(thread_token_info);

            size_t start_addr = thread.Field("Win32StartAddress").GetUlongPtr();

            string start_func_name = getAddrSymbol(start_addr);

			
            ss << "\tThread: <link cmd=\"!thread " << hex << showbase << thread_addr << "\">" << thread_addr << "</link> "
                << "<link cmd=\"dt nt!_ETHREAD " << thread_addr << "\">dt</link> "
                << "<link cmd=\"!dk obj " << thread_addr - 0x30 << "\">detail</link> "                
                << "<link cmd=\".thread " << thread_addr << "; kf;\">switch</link>    "
                << "Cid: " << setw(6) << unique_process << "." << left << setw(6) << unique_thread << right << "    Thread Func: ";


            if (start_func_name.empty())
                ss << "<link cmd=\"u " << start_addr << "\">" << start_addr << "</link>" << endl;
            else
                ss << start_func_name << endl;

            if (thread_token_addr != 0)
            {
                ss << "\t\tImpersonation Token: <link cmd=\"!token " << thread_token_addr << "\">" << thread_token_addr << "</link> "
                    << "<link cmd=\"!dk obj " << thread_token_addr - 0x30 << "\">detail</link> "
                    << "<link cmd=\"dt nt!_TOKEN " << thread_token_addr << "\">dt</link> "
                    << getImpersonationLevel(get<1>(thread_token_info)) << "(" << get<1>(thread_token_info) << ") "
                    << endl;
            }

        }

        Dml(ss.str().c_str());
    }
    FILTER_CATCH;
}


void CTokenExt::dump_pool(size_t addr)
{
	try
	{
		size_t curr_qword = addr;

		stringstream ss;

		bool is_paged_pool = in_paged_pool(curr_qword);
		bool is_nonpaged_pool = in_non_paged_pool(curr_qword);

		bool is_small_pool = in_small_pool_page(curr_qword);

		if (is_paged_pool || is_nonpaged_pool)
		{
			auto pool_entry = is_small_pool ? as_small_pool(curr_qword) : as_large_pool(curr_qword);

			if (get<4>(pool_entry) == 0 && get<3>(pool_entry) == 0)
			{
				ss << " [ unusual pool ] " << "Fail to parse this pool due to limitation"
					<< "<link cmd=\"!pool " << curr_qword << "\"> try !pool</link>" << endl;
			}
			else
			{

				ss << " [ pool ] "
					<< setw(10) << get<5>(pool_entry) << "\t\t"
					<< "<link cmd=\"!dk as_mem " << hex << showbase << get<3>(pool_entry) << " " << get<4>(pool_entry) << ";\">["
					<< get<3>(pool_entry) << ",\t\t"
					<< (curr_qword - get<3>(pool_entry)) << " / "
					<< get<4>(pool_entry) << "]</link>\t\t";

				if (get<0>(pool_entry))
					ss << "Small | ";
				else
					ss << "Large | ";

				if (get<1>(pool_entry))
					ss << "Paged | ";
				else
					ss << "Non-Paged | ";

				if (get<2>(pool_entry))
					ss << "Allocated";
				else
					ss << "Free";

				ss << endl;
			}
		}

		Dml(ss.str().c_str());
	}
	FILTER_CATCH;
}

size_t CTokenExt::find_proc(string name)
{
    try
    {
        ExtRemoteTypedList pses_list = ExtNtOsInformation::GetKernelProcessList();

        for (pses_list.StartHead(); pses_list.HasNode(); pses_list.Next())
        {
            m_Control->ControlledOutput(DEBUG_OUTCTL_ALL_OTHER_CLIENTS
                , DEBUG_OUTPUT_NORMAL, "ps\n");
            ExtRemoteTyped ps = pses_list.GetTypedNode();
            size_t name_addr = pses_list.GetNodeOffset() + ps.GetFieldOffset("ImageFileName");
            char sz_name[16] = { 0, };
            m_Data->ReadVirtual(name_addr, sz_name, 15, NULL);
            
            if (name == sz_name)
                return pses_list.GetNodeOffset();
        }
    }
    FILTER_CATCH;

    return 0;
}

void CTokenExt::dump_free_pool(size_t size)
{
    try
    {
        size -= 0x10;

        size_t paged_pool_des = read<size_t>(readDbgDataAddr(DEBUG_DATA_ExpPagedPoolDescriptorAddr));
        size_t paged_pool_num = read<uint32_t>(readDbgDataAddr(DEBUG_DATA_ExpNumberOfPagedPoolsAddr));

        stringstream ss;
        for (size_t i = 0; i < paged_pool_num; i++)
        {

            size_t paged_pool_descriptor = paged_pool_des + 0x1140 * i;


            ss << hex << showbase
                << "\n" << string(0x40, '*') << "\n"
                << "Paged Pool Metrics :" << paged_pool_descriptor << "\n"
                << setw(20) << "pool index :" << i <<  "\n\n";  


            vector<size_t> pages;
            size_t count = 0;
            size_t j = size / 0x10;
            {

                size_t head = paged_pool_descriptor + 0x140 + 0x10 * j;
                size_t curr = read<size_t>(head);
                while (curr != head)
                {
                    

                    size_t pool_entry = curr;

                    size_t page = pool_entry & 0xFFFFFFFFFFFFF000;
                    if (find(pages.begin(), pages.end(), page) == pages.end() && pool_entry != 0)
                        pages.push_back(page);

                    curr = read<size_t>(curr);                    
                    //ss << "\t<link cmd=\"!pool " << hex << showbase << curr << "\">" << curr << "</link>\n";
                    ss << hex << showbase
                        << "<link cmd=\"dt nt!_POOL_HEADER " << setfill('0') << setw(16) << pool_entry - 0x10
                        << "\">"
                        << setfill('0') << setw(16) << pool_entry
                        << "</link>"
                        << "[<link cmd=\"!pool " << setfill('0') << setw(16) << page
                        << "\">Page " << dec << noshowbase << find(pages.begin(), pages.end(), page) - pages.begin()
                        << "</link>]\t";

                    if (++count % 0x4 == 0 && count != 0)
                        ss << "\n";
                };
                ss << "\n";                   
            }
            ss << endl;

        }

        Dml(ss.str().c_str());
    }
    FILTER_CATCH;
}

void CTokenExt::dump_hole(size_t addr)
{
    try
    {
        //if (valid_addr(addr))
        {
            bool current = false;

            size_t start_page_addr = (addr & 0xFFFFFFFFFFFFF000 - 0x1000 * 0x80) & 0xFFFFFFFFFFF00000;

            stringstream ss;
            ss << "\n++++++++++++++++++++++++++++++++++++++++++++++\n";
            for (size_t i = 0; i < 0x200; i++)
            {
                if (i % 0x10 == 0)
                {
                    if (current)
                    {
                        current = false;
                        ss << "\t\t <-----[" << hex << showbase << setw(16) << setfill('0') << addr;
                    }
                    ss << "\n0x" << hex << showbase << setw(16) << setfill('0') << start_page_addr + i * 0x1000 << ": ";
                }

                if (addr >= start_page_addr + i * 0x1000 && addr <= start_page_addr + (i + 1) * 0x1000)
                    current = true;

                if (valid_addr(start_page_addr + i * 0x1000))
                    ss << "!";
                else
                    ss << ".";
            }

            ss << "\n++++++++++++++++++++++++++++++++++++++++++++++\n";

            Out(ss.str().c_str());
        }
    }
    FILTER_CATCH;
}

void CTokenExt::dump_threads_stack(size_t process_addr)
{
    try
    {
        //size_t process_addr = curr_proc();
        ExtRemoteTyped proc("(nt!_EPROCESS*)@$extin", process_addr);
        size_t thread_list_head_addr = process_addr + proc.GetFieldOffset("ThreadListHead");

        ExtRemoteTypedList threads_list(thread_list_head_addr, "nt!_ETHREAD", "ThreadListEntry");
        for (threads_list.StartHead(); threads_list.HasNode(); threads_list.Next())
        {
            size_t thread_addr = threads_list.GetNodeOffset();

            Out("-------------------------------\n");

            size_t trap_frame_addr = threads_list.GetTypedNode().Field("Tcb.TrapFrame").GetUlongPtr();

            stringstream cmd;
            cmd << ".thread " << hex << showbase << thread_addr << ";"; 

            if (S_OK == x(cmd.str()) && (trap_frame_addr == 0 || valid_addr(trap_frame_addr)))
                x("kf");
        }
    }
    FILTER_CATCH;
}

void CTokenExt::dump_all_threads_stack()
{
    try
    {     
        ExtRemoteTypedList pses_list = ExtNtOsInformation::GetKernelProcessList();

        for (pses_list.StartHead(); pses_list.HasNode(); pses_list.Next())
        {
            size_t proc_addr = pses_list.GetNodeOffset();
            Out("-----------[0x%I64x]-----------\n", proc_addr);
            dump_threads_stack(proc_addr);
        }
    }FILTER_CATCH;
}

void CTokenExt::dig_link(size_t addr)
{
    try
    {
        if (valid_addr(addr))
        {
            size_t next_addr = read<size_t>(addr);
            Out(" --> 0x%I64x", addr);
            if (addr > next_addr)
                Out(" [- 0x%08x] ", addr - next_addr);
            else
                Out(" [+ 0x%08x] ", next_addr - addr);
            dig_link(next_addr);
        }
        else
        {
            Out(" --> 0x%I64x\n", addr);
        }
    }
    FILTER_CATCH;
}

void CTokenExt::tpool(size_t addr)
{
    try
    {
        for (size_t i = 0; i < 0x08; i++)
        {
            size_t item_addr = addr + 0x10 + 0x450 * i;
            Out("[%d] token at 0x%I64x\n", i, item_addr);
            Out("\tnext : 0x%I64x\n", read<size_t>(item_addr));
            Out("\tmodel and size : 0x%08x 0x%08x\n\n", read<uint16_t>(item_addr+0x10), read<uint16_t>(item_addr+0x14));
        }
    }
    FILTER_CATCH;
}

void CTokenExt::poolhdr(size_t addr)
{
    try
    {
        uint8_t prev_size = read<uint8_t>(addr);
        uint8_t pool_index = read<uint8_t>(addr + 1);
        uint8_t block_size = read<uint8_t>(addr + 2);
        uint8_t pool_type = read<uint8_t>(addr + 3);

        char tag[5] = { 0, };
        tag[0] = read<uint8_t>(addr + 4);
        tag[1] = read<uint8_t>(addr + 5);
        tag[2] = read<uint8_t>(addr + 6);
        tag[3] = read<uint8_t>(addr + 7);

        uint16_t allocator_bt_index = read<uint16_t>(addr + 0x08);
        uint16_t pool_tag_hash = read<uint16_t>(addr + 0x0A);

        size_t process_billed = read<size_t>(addr + 0x08);

        Out("%30s : 0x%02x\n", "Prev Size", (uint16_t)prev_size);
        Out("%30s : 0x%02x\n", "Pool Index", (uint16_t)pool_index);
        Out("%30s : 0x%02x\n", "Block Size", (uint16_t)block_size);
        Out("%30s : 0x%02x\n", "Pool Type", (uint16_t)pool_type);
        Out("%30s : 0x%s\n", "Tag", tag);
        Out("%30s : 0x%04x\n", "Allocator BT Index", allocator_bt_index);
        Out("%30s : 0x%04x\n", "Pool Tag Hash", pool_tag_hash);
        Out("%30s : 0x%I64x\n", "Process Billed", process_billed);

        if ((string)tag == "Free")
        {
            size_t prev_free = read<size_t>(addr + 0x10);
            size_t next_free = read<size_t>(addr + 0x18);

            Out("%30s : 0x%I64x\n", "Prev Free", prev_free);
            Out("%30s : 0x%I64x\n", "Next Free", next_free);
        }
    }
    FILTER_CATCH;
}


void CTokenExt::dump_page_info(size_t addr)
{
	size_t pxe_index = (addr >> 39) & 0x1FF;
	size_t ppe_index = (addr >> 30) & 0x1FF;
	size_t pde_index = (addr >> 21) & 0x1FF;
	size_t pte_index = (addr >> 12) & 0x1FF;
	size_t offset = addr & 0xFFF;

	stringstream ss;

	size_t cr3 = get_cr3();

	PTE64 pxe(readX<size_t>(cr3 + pxe_index * 8));
	PTE64 ppe(pxe.valid()? readX<size_t>(pxe.PFN() + ppe_index * 8) : 0);
	PTE64 pde(ppe.valid()? readX<size_t>(ppe.PFN() + pde_index * 8) : 0);
	PTE64 pte(pde.valid()? readX<size_t>(pde.PFN() + pte_index * 8) : 0);

	size_t paddr = pte.PFN();

	ss << hex << showbase
		<< "PXE: Valid=" << (pxe.valid() ? "Y" : "n") << ", Index=" << setw(6) << pxe_index << ", PFN=" << setw(18) << pxe.PFN() << ", Flags=" << pxe.str() << endl
		<< "PPE: Valid=" << (ppe.valid() ? "Y" : "n") << ", Index=" << setw(6) << ppe_index << ", PFN=" << setw(18) << ppe.PFN() << ", Flags=" << ppe.str() << endl
		<< "PDE: Valid=" << (pde.valid() ? "Y" : "n") << ", Index=" << setw(6) << pde_index << ", PFN=" << setw(18) << pde.PFN() << ", Flags=" << pde.str() << endl
		<< "PTE: Valid=" << (pte.valid() ? "Y" : "n") << ", Index=" << setw(6) << pte_index << ", PFN=" << setw(18) << pte.PFN() << ", Flags=" << pte.str() << endl
		<< "Virtual Address: " << setw(18) << addr << endl
		<< "Physical Address: " << setw(18) << (pte.PFN() + offset) << endl << endl;

	Out(ss.str().c_str());
}

void CTokenExt::dump_pages_around(size_t addr)
{
	size_t pxe_index = (addr >> 39) & 0x1FF;
	size_t ppe_index = (addr >> 30) & 0x1FF;
	size_t pde_index = (addr >> 21) & 0x1FF;
	size_t pte_index = (addr >> 12) & 0x1FF;
	size_t offset = addr & 0xFFF;

	stringstream ss;

	size_t cr3 = get_cr3();

	PTE64 pxe(readX<size_t>(cr3 + pxe_index * 8));
	PTE64 ppe(pxe.valid() ? readX<size_t>(pxe.PFN() + ppe_index * 8) : 0);
	PTE64 pde(ppe.valid() ? readX<size_t>(ppe.PFN() + pde_index * 8) : 0);

	size_t* pde_entries = new size_t[0x200];
	memset(pde_entries, 0, 0x1000);

	if (pxe.valid() && ppe.valid() && pde.valid())
	{
		auto status = m_Data->ReadPhysical(pde.PFN(), pde_entries, 0x1000, NULL);
		if (S_OK != status)
			ThrowRemote(E_ACCESSDENIED, "Fail to read memory");
	}

	for (size_t i = 0; i < 0x200; i++)
	{
		PTE64 pte(pde_entries[i]);

		ss << hex << showbase
			<< setw(18) << ((addr & 0xFFFFFFFFFFE00000) + i * 0x1000) << " : ";

		if (pte.valid())
			ss << setw(18) << pte.PFN();

		if (i == pte_index)
			ss << "\t\t<---------------- [" << addr << " ]";

		ss << endl;
	}

	delete[] pde_entries;

	Dml("<link cmd=\"!dk pages 0x%I64x\"> Previous </link>\n", addr - 0x200000);
	Out(ss.str().c_str());
	Dml("<link cmd=\"!dk pages 0x%I64x\"> Next </link>\n", addr + 0x200000);
}

void CTokenExt::dump_pool_metrics()
{
    try
    {
        size_t exp_pool_flags_addr = getSymbolAddr("nt!ExpPoolFlags");
        uint32_t exp_pool_flags = read<uint32_t>(exp_pool_flags_addr);
        Out("nt!ExpPoolFlags: 0x%08x\n", exp_pool_flags);

        size_t exp_session_pool_la_addr = getSymbolAddr("nt!ExpSessionPoolLookaside");
        size_t exp_session_pool_la = read<size_t>(exp_session_pool_la_addr);
        Out("nt!ExpSessionPoolLookaside: 0x%I64x\n", exp_session_pool_la_addr);

        uint32_t exp_session_pool_small_lists = read<uint32_t>(getSymbolAddr("nt!ExpSessionPoolSmallLists"));
        Out("nt!ExpSessionPoolSmallLists: 0x%08x\n", exp_session_pool_small_lists);

        uint32_t exp_number_of_paged_pools = read<uint32_t>(getSymbolAddr("nt!ExpNumberOfPagedPools"));
        Out("nt!ExpNumberOfPagedPools: 0x%08x\n", exp_number_of_paged_pools);

        uint32_t exp_number_of_non_paged_pools = read<uint32_t>(getSymbolAddr("nt!ExpNumberOfNonPagedPools"));
        Out("nt!ExpNumberOfNonPagedPools: 0x%08x\n", exp_number_of_non_paged_pools);

        size_t exp_paged_pool_descriptor = read<size_t>(getSymbolAddr("nt!ExpPagedPoolDescriptor"));
        Out("nt!ExpPagedPoolDescriptor: 0x%I64x\n", getSymbolAddr("nt!ExpPagedPoolDescriptor"));

        size_t exp_non_paged_pool_descriptor = read<size_t>(getSymbolAddr("nt!ExpNonPagedPoolDescriptor"));
        Out("nt!ExpNonPagedPoolDescriptor: 0x%I64x\n", getSymbolAddr("nt!ExpNonPagedPoolDescriptor"));


    }
    FILTER_CATCH;
}

void CTokenExt::dump_pe_guid(size_t addr)
{
    try
    {
        size_t dos_magic = read<size_t>(addr);

        if (dos_magic != 0x0000000300905a4d)
            return;

        uint32_t e_lfanew = read<uint32_t>(addr + 0x3C);
        
        uint32_t nt_magic = read<uint32_t>(addr + e_lfanew);
        if (nt_magic != 0x00004550)
            return;

        uint32_t timestamp = read<uint32_t>(addr + e_lfanew + 0x08);
        uint32_t sizeof_image = read<uint32_t>(addr + e_lfanew + 0x50);

        Out("guid : http://msdl.microsoft.com\/download\/symbols\/[xxx]\/%08X%08X\/[xxx]\n", timestamp, sizeof_image);
    }
    FILTER_CATCH;
}

void CTokenExt::dump_session_pool()
{
    try
    {
        size_t proc_addr = curr_proc();
        size_t session_addr = read<size_t>(proc_addr + 0x400);

        size_t this_session_addr = session_addr;
        dump_session_space(this_session_addr);
        session_addr = read<size_t>(session_addr + 0x98) - 0x90;
        while (session_addr != this_session_addr)
        {
            if ((session_addr & 0x00000FFF) == 0x000)
                dump_session_space(session_addr);

            session_addr = read<size_t>(session_addr + 0x98) - 0x90;
        }
    }
    FILTER_CATCH;
}

void CTokenExt::dump_session_space(size_t addr)
{
    uint32_t session_id = read<uint32_t>(addr + 0x08);

    Out("Session : %d\n", session_id);

    stringstream ss;
    ss.str("");
    ss << "dt nt!_POOL_DESCRIPTOR "
        << hex << showbase << addr + 0xcc0
        << "";

    x(ss.str());
}

void CTokenExt::dump_page_dir(size_t proc_addr, bool user_mode_only)
{
    try
    {
        size_t page_dir_addr = read<size_t>(proc_addr + 0x28);
        for (size_t i = 0; i < (user_mode_only ? 0x100 : 0x200); i++)
        {
            PTE64 pte = { 0, };
            size_t entry = readX<size_t>(page_dir_addr + 0x08 * i);
            memcpy(&pte, &entry, sizeof(size_t));

            stringstream ss;
            if (entry != 0)
            {
                ss << hex << noshowbase << setfill('0')
                    << "PML4 entry [0x " << setw(2) << i << " ] "
                    << "0x" << setw(16) << pte.PFN() << " , "
                    << "0x" << setw(16) << i * 0x8000000000 << " - "
                    << "0x" << setw(16) << (i + 1) * 0x8000000000 - 1 << " "
                    << pte.str()
                    << "\n";

                Out(ss.str().c_str());
                //Out("PML4 entry [%02x] 0x%I64x 0x%I64x - 0x%I64x\n", i, pte.PFN(), i * 0x7FFFFFFFFF, (i+1)*0x7FFFFFFFFF - 1);
            }

        }
    }
    FILTER_CATCH;
}

string CTokenExt::dump_obj_ref(size_t addr)
{
    try
    {
        size_t ptr_count = read<size_t>(addr - 0x30);
        size_t handle_count = read<size_t>(addr - 0x28);

        size_t real_ptr_count = ptr_count;

        stringstream ss;

        ss << hex << showbase
            << setw(18) << ptr_count << "(" << real_ptr_count << ")"
            << setw(18) << handle_count << "\n";

        return ss.str();
    }
    FILTER_CATCH;

    return "";
}

bool CTokenExt::VisitSide(size_t addr, vector<size_t>& entries)
{
    try
    {
        size_t parent = read<size_t>(addr);
        size_t left = read<size_t>(addr + 0x08);
        size_t right = read<size_t>(addr + 0x10);

        if (left != 0)
        {
            entries.push_back(left);
            VisitSide(left, entries);
        }

        if (right != 0)
        {
            entries.push_back(right);
            VisitSide(right, entries);
        }

    }FILTER_CATCH;
    return true;
}

vector<size_t> CTokenExt::dump_avl_entries(size_t addr)
{
    vector<size_t> entries;
    try
    {

        VisitSide(addr, entries);

    }
    FILTER_CATCH;

    return entries;
}

string CTokenExt::ctime(time_t * time)
{
    struct tm * timeinfo;
    char buffer[80];

    timeinfo = localtime(time);
    if (timeinfo)
        strftime(buffer, 80, "%F %T", timeinfo);
    return string(buffer);
}

string CTokenExt::fctime(time_t * time)
{
    struct tm * timeinfo;
    char buffer[80];

    timeinfo = localtime(time);
    if (timeinfo)
        strftime(buffer, 80, "%Y_%m_%d_%H_%M_%S", timeinfo);
    return string(buffer);
}

HRESULT CTokenExt::x(string cmd)
{
    try
    {
        return m_Control->Execute(DEBUG_OUTCTL_ALL_CLIENTS, cmd.c_str(), DEBUG_EXECUTE_ECHO);
    }
    FILTER_CATCH;

    return S_FALSE;
}

string CTokenExt::x_output(string cmd)
{
	try
	{
		m_Control->Execute(DEBUG_OUTCTL_ALL_CLIENTS, cmd.c_str(), DEBUG_EXECUTE_ECHO);

		return m_last_cmd_output;
	}
	FILTER_CATCH;

	return "";
}

size_t CTokenExt::reg(size_t reg)
{
    try
    {
        DEBUG_VALUE reg_val = { 0, };
        m_Registers->GetValue(reg, &reg_val);

        return reg_val.I64;
    }
    FILTER_CATCH;

    return 0;
}

size_t CTokenExt::reg_of(const char* reg_v)
{
    static map<const char*, size_t, cmp_str> regs_map{
        {"rip", REG_RIP}, {"rbp", REG_RBP}, {"rsp", REG_RSP},
        {"rax", REG_RAX}, {"rbx", REG_RBX}, {"rcx", REG_RCX}, {"rdx", REG_RDX},
        {"rsi", REG_RSI}, {"rdi", REG_RDI},
        {"r8", REG_R8},{ "r9", REG_R9 },{ "r10", REG_R10 },{ "r11", REG_R11 },{ "r12", REG_R12 },{ "r13", REG_R13 },{ "r14", REG_R14 },{ "r15", REG_R15 }
    };

    uint32_t index = 0;
    if (m_Registers->GetIndexByName(reg_v, (PULONG)&index) == S_OK)
    {
        return reg(index);
    }

    if (regs_map.find(reg_v) == regs_map.end())
        return 0;

    return reg(regs_map[reg_v]);
}

tuple<size_t, size_t> CTokenExt::get_thread_token(size_t thread_addr)
{
    size_t token = 0;
    size_t level = 0;
    try
    {
        ExtRemoteTyped thread("(nt!_ETHREAD*)@$extin", thread_addr);
        bool impersonating = (thread.Field("CrossThreadFlags").GetUlong() & 8) != 0;
        if (impersonating)
        {
            token = thread.Field("ClientSecurity.ImpersonationToken").GetUlongPtr() & 0xFFFFFFFFFFFFFFF8;
            level = thread.Field("ClientSecurity.ImpersonationLevel").GetUlong64();
        }
    }
    FILTER_CATCH;
    return make_tuple(token, level);
}

string CTokenExt::dump_luid(size_t addr)
{
    try
    {
        ExtRemoteTyped luid("(nt!_LUID*)@$extin", addr);
        stringstream ss;
        ss << showbase << hex << setw(16) << read<size_t>(addr) << " ";
        ss << "[HighPart:" << showbase << hex << setw(8) << luid.Field("HighPart").GetUlong() << ", ";
        ss << "LowPart:" << showbase << hex << setw(8)  << luid.Field("LowPart").GetUlong() << "]";

        return ss.str();
    }
    FILTER_CATCH;
    return "";
}

string CTokenExt::dump_acl(size_t acl_addr, string type_name)
{
    try
    {
        uint8_t version = read<uint8_t>(acl_addr);
        uint16_t entry_count = read<uint16_t>(acl_addr + 4);
        size_t entry_addr = acl_addr + 8;
        stringstream ss;

        for (size_t i = 0; i < entry_count; i++)
        {
            uint8_t type = read<uint8_t>(entry_addr + 0);
            uint32_t mask = read<uint32_t>(entry_addr + 4);
            uint16_t size = read<uint16_t>(entry_addr + 2);
            size_t sid_addr = entry_addr + 8;
            string sid_str = dump_sid(sid_addr);
			ss << hex << setw(2) << setfill('0') << uint32_t(type) << " " << setw(20) << setfill(' ') << getAceTypeStr(type) << " "
                << hex << setw(4) << setfill('0') << mask << " " << setw(50) << setfill(' ')
                << sid_str << "\t\t"
				<< getAceMaskStr(mask, type_name) << " ";
            if (type == 0x11)
                ss << " [" << getIntegrityLevel(sid_str) << "]";
            else if (type == 0x14)
                ss << " [" << getTrustLabel(sid_str) << "]";
            ss << "\n";
			
            entry_addr += size;
        }
        return ss.str();
    }
    FILTER_CATCH;

    return "";
}

string CTokenExt::dump_privilege(size_t addr)
{
    stringstream ss;
    try
    {
        ExtRemoteTyped privilege("(nt!_SEP_TOKEN_PRIVILEGES*)@$extin", addr);
        ss << setw(32) << setfill(' ') << "Present: 0x" << hex << setw(16) << setfill('0') << privilege.Field("Present").GetUlong64() << "\n" 
            << dump_privileges_by_bitmap(privilege.Field("Present").GetUlong64()) << "\n";
        ss << setw(32) << setfill(' ') << "Enabled: 0x" << hex << setw(16) << setfill('0') << privilege.Field("Enabled").GetUlong64() << "\n"
            << dump_privileges_by_bitmap(privilege.Field("Enabled").GetUlong64()) << "\n";
        ss << setw(32) << setfill(' ') << "EnabledByDefault: 0x" << hex << setw(16) << setfill('0') << privilege.Field("EnabledByDefault").GetUlong64() << "\n"
            << dump_privileges_by_bitmap(privilege.Field("EnabledByDefault").GetUlong64()) << "\n";
    }
    FILTER_CATCH;
    return ss.str();
}

string CTokenExt::dump_privileges_by_bitmap(size_t bitmap)
{
    stringstream ss;
    for (size_t i = 2; i <= 0x23; i++)
    {
        if (bitmap & (1 << i))
        {
            ss << "0x" << hex << setw(2) << setfill('0') << i << " " << privilege_bit_to_text(i) << "\n";
        }
    }
    return ss.str();
}

string CTokenExt::privilege_bit_to_text(size_t bit_offset)
{
    switch (bit_offset)
    {
    case 0x02:
        return "SeCreateTokenPrivilege";  
    case 0x03:
        return "SeAssignPrimaryTokenPrivilege";
    case 0x04:
        return "SeLockMemoryPrivilege";
    case 0x05:
        return "SeIncreaseQuotaPrivilege";
    case 0x06:
        return "SeMachineAccountPrivilege";
    case 0x07:
        return "SeTcbPrivilege";
    case 0x08:
        return "SeSecurityPrivilege";
    case 0x09:
        return "SeTakeOwnershipPrivilege";
    case 0x0A:
        return "SeLoadDriverPrivilege";
    case 0x0B:
        return "SeSystemProfilePrivilege";
    case 0x0C:
        return "SeSystemtimePrivilege";
    case 0x0D:
        return "SeProfileSingleProcessPrivilege";
    case 0x0E:
        return "SeIncreaseBasePriorityPrivilege";
    case 0x0F:
        return "SeCreatePagefilePrivilege";
    case 0x10:
        return "SeCreatePermanentPrivilege";
    case 0x11:
        return "SeBackupPrivilege";
    case 0x12:
        return "SeRestorePrivilege";
    case 0x13:
        return "SeShutdownPrivilege";
    case 0x14:
        return "SeDebugPrivilege";
    case 0x15:
        return "SeAuditPrivilege";
    case 0x16:
        return "SeSystemEnvironmentPrivilege";
    case 0x17:
        return "SeChangeNotifyPrivilege";
    case 0x18:
        return "SeRemoteShutdownPrivilege";
    case 0x19:
        return "SeUndockPrivilege";
    case 0x1A:
        return "SeSyncAgentPrivilege";
    case 0x1B:
        return "SeEnableDelegationPrivilege";
    case 0x1C:
        return "SeManageVolumePrivilege";
    case 0x1D:
        return "SeImpersonatePrivilege";
    case 0x1E:
        return "SeCreateGlobalPrivilege";
    case 0x1F:
        return "SeTrustedCredManAccessPrivilege";
    case 0x20:
        return "SeRelabelPrivilege";
    case 0x21:
        return "SeIncreaseWorkingSetPrivilege";
    case 0x22:
        return "SeTimeZonePrivilege";
    case 0x23:
        return "SeCreateSymbolicLinkPrivilege";
    default:
        return "";
    }
    return "";
}

void CTokenExt::do_memcpy(size_t src_addr, size_t dst_addr, size_t count)
{
    try
    {
        size_t qwords = count / 0x08;
        size_t bytes = count % 0x08;

        for (size_t i = 0; i < qwords; i++)
        {
            size_t temp_qword = read<size_t>(src_addr + i * 0x08);
            write<size_t>(dst_addr + i * 0x08, temp_qword);
        }

        for (size_t i = 0; i < bytes; i++)
        {
            uint8_t byte = read<uint8_t>(src_addr + qwords * 0x08 + i);
            write<uint8_t>(dst_addr + qwords * 0x08 + i, byte);
        }
    }
    FILTER_CATCH;
}

void 
CTokenExt::dump_obj_dir(
    size_t obj_dir_addr,
    size_t level, 
    bool recurse)
{
    if (obj_dir_addr == 0)
        return;

    try
    {
        /*ExtRemoteTyped obj_hdr("(nt!_OBJECT_HEADER*)@$extin", obj_hdr_addr);
        uint8_t info_mask = obj_hdr.Field("InfoMask").GetUchar();
        size_t obj_dir_addr = 0;
        if (info_mask & 0x02)
        {
            size_t mask2off_table_addr = getSymbolAddr("nt!ObpInfoMaskToOffset");
            uint8_t offset = read<uint8_t>(mask2off_table_addr + (info_mask & 3));

            ExtRemoteTyped ob_type_entry("(nt!_OBJECT_HEADER_NAME_INFO*)@$extin", obj_hdr_addr - offset);
            obj_dir_addr = ob_type_entry.Field("Directory").GetUlongPtr();
        }*/

        //size_t obj_dir_addr = obj_hdr_addr + 0x30;
        if (obj_dir_addr == 0)
            return;

		stringstream ss;

		dump_obj(obj_dir_addr - 0x30);

		Out(string(60, '=').append("\n").c_str());

        for (size_t i = 0; i < 37; i++)
        {
            size_t entry = read<size_t>(obj_dir_addr + 8 * i);
            if (!valid_addr(entry))
                continue;
            if (entry == obj_dir_addr)
                continue;

            while (valid_addr(entry))
            {
                size_t obj_addr = read<size_t>(entry + 8);
                if (valid_addr(obj_addr - 0x30))
                {
                    ExtRemoteTyped obj_hdr("(nt!_OBJECT_HEADER*)@$extin", obj_addr - 0x30);  
                    string type_name = wstr2str(getTypeName(realIndex(obj_hdr.Field("TypeIndex").GetUchar(), obj_addr - 0x30)));
                    string tab(level*4, ' ');
                    tab += "->";

					ss.str("");

					ss << tab << showbase << hex << setw(4) << i
						<< " [" << setw(20) << type_name << "]     ";

					if (type_name == "File")
						ss << setw(50) << wstr2str(dump_file_name(obj_addr - 0x30));
					else
						ss << setw(50) << wstr2str(dump_obj_name(obj_addr - 0x30));

					ss << " <link cmd=\"dt _OBJECT_HEADER " << obj_addr - 0x30 << "\">" << obj_addr - 0x30 << "</link> ";

					if (type_name == "Directory")
						ss << " <link cmd=\"!dk obj " << obj_addr - 0x30 << "\">detail</link> <link cmd=\"!dk obj_dir " << obj_addr << "\">listdir</link>" << endl;
					else
						ss << " <link cmd=\"!dk obj " << obj_addr - 0x30 << "\">detail</link>" << endl;

					Dml(ss.str().c_str());

                    /*if (type_name == L"File")
                        Out(L"%s%02x %20s %s\n", tab.c_str(), i, type_name.c_str(), dump_file_name(obj_addr - 0x30).c_str());
                    else
                        Out(L"%s%02x %20s %s\n", tab.c_str(), i, type_name.c_str(), dump_obj_name(obj_addr - 0x30).c_str());
*/
                    //dump_obj(obj_addr-0x30, true);

/*                    if (recurse && type_name == "Directory")
                        dump_obj_dir(obj_addr-0x30, level+1);     */  
                }
                size_t next = read<size_t>(entry);
                if (next == entry)
                    break;
                entry = next;
            }
        }
    }
    FILTER_CATCH;
}

size_t CTokenExt::getSymbolAddr(const char * name)
{
    size_t addr = 0;
    try
    {
        m_Symbols->GetOffsetByName(name, &addr);
    }
    FILTER_CATCH;
    return addr;
}

string CTokenExt::getAddrSymbol(size_t addr)
{
    string name;
    try
    {
        char* symbol = nullptr;
        ULONG len = 0;
        if (S_OK == m_Symbols->GetNameByOffset(addr, symbol, 0, &len, 0))
        {
            symbol = new (nothrow) char[len];
            if (symbol != nullptr &&
                S_OK == m_Symbols->GetNameByOffset(addr, symbol, len, &len, 0))
                name = symbol;

            if (symbol != nullptr)
                delete[] symbol;
        }
    }
    FILTER_CATCH;
    return name;
}

string CTokenExt::getProtectionText(uint8_t protection)
{
    string text;

    switch (protection & 0x0F)
    {
    case 0x01:
        text += "[PPL ";
        break;
    case 0x02:
        text += "[PP  ";
        break;
    default:
        return "";
        break;
    }

    switch (protection & 0xF0)
    {
    case 0x00:
        text += "None]";
        break;
    case 0x10:
        text += "AuthCode]";
        break;
    case 0x20:
        text += "CodeGen]";
        break;
    case 0x30:
        text += "AntiMal]";
        break;
    case 0x40:
        text += "Lsa]";
        break;
    case 0x50:
        text += "Windows]";
        break;
    case 0x60:
        text += "Tcb]";
        break;
	case 0x70:
		text += "System]";
		break;
    default:
        return "";
        break;
    }
    return text;
}

string CTokenExt::getTokenIL(size_t token_addr)
{
    try
    {
        ExtRemoteTyped token("(nt!_TOKEN*)@$extin", token_addr);
        size_t il_sid_addr = token.Field("IntegrityLevelSidValue").GetUlongPtr();
        if (il_sid_addr != 0)
            return getIntegrityLevel(dump_sid(il_sid_addr));

        size_t il_index = token.Field("IntegrityLevelIndex").GetUlong();
        string il_str = get_sid_attr_hash_item(token_addr + token.GetFieldOffset("SidHash"), il_index);
        return getIntegrityLevel(il_str);
    }
    FILTER_CATCH;

    return "";
}

bool CTokenExt::valid_addr(size_t addr)
{
    bool valid = true;
    try
    {
        read<uint8_t>(addr);
    }
    catch (ExtException& e)
    {
        valid = false;
    }
    
    return valid;
}

wstring CTokenExt::readUnicodeString(size_t addr)
{
    wstring name;
    try
    {
        ExtRemoteTyped us("(nt!_UNICODE_STRING*)@$extin", addr);
        size_t name_addr = us.Field("Buffer").GetLongPtr();
        size_t name_len = us.Field("Length").GetUshort();
        wchar_t* obj_name_buf = new wchar_t[name_len / 2 + 1];
        memset(obj_name_buf, 0, (name_len / 2 + 1) * sizeof(wchar_t));
        if (S_OK == m_Data->ReadVirtual(name_addr, obj_name_buf, name_len, NULL))
            name = obj_name_buf;

        delete[] obj_name_buf;
    }
    FILTER_CATCH;
    
    return name;
}

wstring CTokenExt::dump_obj_name(size_t obj_hdr_addr)
{
    wstring obj_name;

    try
    {
        ExtRemoteTyped obj_hdr("(nt!_OBJECT_HEADER*)@$extin", obj_hdr_addr);
        uint8_t info_mask = obj_hdr.Field("InfoMask").GetUchar();
        if (info_mask & 0x02)
        {
            size_t mask2off_table_addr = getSymbolAddr("nt!ObpInfoMaskToOffset");
            uint8_t offset = read<uint8_t>(mask2off_table_addr + (info_mask & 3));

            ExtRemoteTyped ob_type_entry("(nt!_OBJECT_HEADER_NAME_INFO*)@$extin", obj_hdr_addr - offset);             
            obj_name = readUnicodeString(obj_hdr_addr - offset + ob_type_entry.GetFieldOffset("Name"));  

            wstring type_name = getTypeName(realIndex(obj_hdr.Field("TypeIndex").GetUchar(), obj_hdr_addr));
            if (type_name == L"SymbolicLink")
            {
                obj_name += L" --> ";
                obj_name += dump_sym_link(obj_hdr_addr);
            }
        }
    }
    FILTER_CATCH;

    return obj_name;
}

wstring CTokenExt::dump_file_name(size_t file_obj_addr)
{
    try
    {
        ExtRemoteTyped file_obj("(nt!_FILE_OBJECT*)@$extin", file_obj_addr);
        return readUnicodeString(file_obj_addr + file_obj.GetFieldOffset("FileName"));
    }
    FILTER_CATCH;

    return L"";
}

wstring CTokenExt::dump_sym_link(size_t addr)
{
    wstring obj_name;

    try
    {
        ExtRemoteTyped obj_sym_link("(nt!_OBJECT_SYMBOLIC_LINK*)@$extin", addr+0x30);        
        obj_name = readUnicodeString(addr + 0x30 + obj_sym_link.GetFieldOffset("LinkTarget"));
    }
    FILTER_CATCH;

    return obj_name;
}

void CTokenExt::dump_big_pool()
{
	uint8_t* page_x3_buffer = new uint8_t[0x3000];

    try
    {
        size_t big_pool_addr = read<size_t>(getSymbolAddr("nt!PoolBigPageTable"));
        size_t big_pool_size = read<size_t>(getSymbolAddr("nt!PoolBigPageTableSize"));

        stringstream ss;

		size_t item_count = 0;
		size_t page_x3_index = 0;

        for (size_t item_addr = big_pool_addr; item_count <  big_pool_size; item_addr += 0x18)
        {
			if ((item_count % 0x200) == 0)
			{
				size_t bytes_read = 0;
				m_Data->ReadVirtual(big_pool_addr + page_x3_index * 0x3000, page_x3_buffer, 0x3000, (PULONG)&bytes_read);

				page_x3_index++;
			}

			item_count++;

			CBigPoolHeader pool_entry(page_x3_buffer + 0x18 * (item_count % 0x200));

			if (!like_kaddr(pool_entry.va))
				continue;		

			bool b_free = ((pool_entry.va & 0x1) == 0x1);
			
            ss.str("");
			ss << hex << showbase
				<< setw(8) << item_count << " "
				<< setw(10) << (b_free ? "Free" : "Allocated") << " "
				<< setw(18) << pool_entry.va << ", "
				<< setw(18) << pool_entry.size << " "
				<< "[" << pool_entry.tag << "] "
				<< setw(10) << pool_entry.pool_type << " ";
            
			
			if ((pool_entry.pool_type & 0x1) != 0)
				ss << "Paged Pool ";
			else
				ss << "Non-Paged Pool ";

            if ((pool_entry.pool_type & 0x200) != 0)
                ss << "| NX ";
			if ((pool_entry.pool_type & 0x20) != 0)
				ss << "| SessionPool ";
			if ((pool_entry.pool_type & 0x4) != 0)
				ss << "| CacheAligned ";
			if ((pool_entry.pool_type & 0x2) != 0)
				ss << "| MustSucceed ";
            
            ss << endl;

            Out(ss.str().c_str());

        }
    }
    FILTER_CATCH;

	delete[] page_x3_buffer;
}

void CTokenExt::dump_pool_track()
{
    try
    {
        size_t pool_track_addr = read<size_t>(getSymbolAddr("nt!PoolTrackTable"));
        size_t pool_track_size = read<size_t>(getSymbolAddr("nt!PoolTrackTableSize"));

        stringstream ss;
        for (size_t item_addr = pool_track_addr; item_addr < pool_track_addr + pool_track_size;item_addr += 0x28)
        {
            uint8_t tag[5] = { 0, };
            tag[0] = read<uint8_t>(item_addr + 0);
            tag[1] = read<uint8_t>(item_addr + 1);
            tag[2] = read<uint8_t>(item_addr + 2);
            tag[3] = read<uint8_t>(item_addr + 3);

            uint32_t np_alloc = read<uint32_t>(item_addr + 0x04);
            uint32_t np_free = read<uint32_t>(item_addr + 0x08);
            size_t np_bytes = read<size_t>(item_addr + 0x10);

            uint32_t p_alloc = read<uint32_t>(item_addr + 0x18);
            uint32_t p_free = read<uint32_t>(item_addr + 0x1C);
            size_t p_bytes = read<size_t>(item_addr + 0x20);

            ss.str("");
            ss << hex << showbase
                << "[" << tag << "] "
                << setw(10) << np_alloc << " A-F "
                << setw(10) << np_free << " "
                << setw(18) << np_bytes << " bytes, "
                << setw(10) << p_alloc << " A-F "
                << setw(10) << p_free << " "
                << setw(18) << p_bytes << " bytes";

            ss << endl;

            Out(ss.str().c_str());
        }
    }
    FILTER_CATCH;
}

void CTokenExt::dump_pool_range()
{
    try
    {
        vector<POOL_METRICS> pool_metrics;

        size_t vector_pool_addr = getSymbolAddr("nt!PoolVector");
        size_t non_paged_pool_addr = read<size_t>(vector_pool_addr);
        size_t paged_pool_addr = read<size_t>(vector_pool_addr + 8);

        size_t non_paged_pool_count = read<uint32_t>(getSymbolAddr("nt!ExpNumberOfNonPagedPools"));
        size_t paged_pool_count = read<uint32_t>(getSymbolAddr("nt!ExpNumberOfPagedPools"));


        size_t mi_state_addr = getSymbolAddr("nt!MiState");
        ExtRemoteTyped mi_state("(nt!_MI_SYSTEM_INFORMATION*)@$extin", mi_state_addr);      


        auto system_node_info = mi_state.Field("Hardware.SystemNodeInformation");
        size_t non_paged_pool_start = system_node_info.Field("NonPagedPoolFirstVa").GetUlong64();

        size_t non_paged_pool_end = non_paged_pool_start;
        for (size_t i = 0; i < 3; i++)
        {
            size_t size_of_bitmap = system_node_info.Field("NonPagedBitMap").ArrayElement(i).Field("SizeOfBitMap").GetUlong64();
            non_paged_pool_end = max(non_paged_pool_end, non_paged_pool_start + size_of_bitmap * 0x08);
        }

        auto dyn_bitmap_paged_pool = mi_state.Field("SystemVa.DynamicBitMapPagedPool");
        size_t paged_pool_start = dyn_bitmap_paged_pool.Field("BaseVa").GetUlong64();
        size_t paged_pool_end = paged_pool_start + dyn_bitmap_paged_pool.Field("MaximumSize").GetUlong64() * 0x1000;

        ExtRemoteTypedList pses_list = ExtNtOsInformation::GetKernelProcessList();

        set<size_t> session_addrs;

        
        for (pses_list.StartHead(); pses_list.HasNode(); pses_list.Next())
        {
            ExtRemoteTyped proc_node = pses_list.GetTypedNode();
            size_t proc_addr = pses_list.GetNodeOffset();

            size_t session_addr = proc_node.Field("Session").GetUlong64();

            if (session_addr != 0)
                session_addrs.insert(session_addr);
        }

        for (auto& session_addr : session_addrs)
        {
            ExtRemoteTyped session_space("(nt!_MM_SESSION_SPACE*)@$extin", session_addr);

            auto session_paged_pool = session_space.Field("PagedPool");

            POOL_METRICS session_pool_metrics = { 0, };
            session_pool_metrics._pool_start = session_space.Field("PagedPoolStart").GetUlong64();
            session_pool_metrics._pool_end = session_space.Field("PagedPoolEnd").GetUlong64();
            stringstream ss;
            ss << "Session " << session_space.Field("SessionId").GetUlong();
            session_pool_metrics._comment = ss.str();

            size_t pending_frees = session_paged_pool.Field("PendingFrees.Next").GetUlong64();
            size_t pending_free_depth = session_paged_pool.Field("PendingFreeDepth").GetUlong();
            size_t curr = pending_frees;
            
            size_t session_pool_desc_addr = session_addr + session_space.GetTypeFieldOffset("nt!_MM_SESSION_SPACE", "PagedPool");
            session_pool_metrics._pool_addr = session_pool_desc_addr;

            pool_metrics.push_back(session_pool_metrics);
        }

        for (size_t i = 0; i < non_paged_pool_count; i++)
        {
            ExtRemoteTyped non_paged_pool("(nt!_POOL_DESCRIPTOR*)@$extin", non_paged_pool_addr + i * 0x1140);

            POOL_METRICS non_paged_pool_metrics = { 0, };
            non_paged_pool_metrics._pool_addr = non_paged_pool_addr + i * 0x1140;
            non_paged_pool_metrics._pool_start = non_paged_pool_start;
            non_paged_pool_metrics._pool_end = non_paged_pool_end;
            non_paged_pool_metrics._pool_index = non_paged_pool.Field("PoolIndex").GetUlong();
            non_paged_pool_metrics._pool_type = non_paged_pool.Field("PoolType").GetUlong();
            non_paged_pool_metrics._total_bytes = non_paged_pool.Field("BytesAllocated").GetUlong64();
            non_paged_pool_metrics._total_pages = non_paged_pool.Field("PagesAllocated").GetUlong64();
            non_paged_pool_metrics._total_big_pages = non_paged_pool.Field("BigPagesAllocated").GetUlong64();
            stringstream ss;
            ss << "Non-Paged Pool " << i;
            non_paged_pool_metrics._comment = ss.str();

            size_t pending_frees = non_paged_pool.Field("PendingFrees.Next").GetUlong64();
            size_t pending_free_depth = non_paged_pool.Field("PendingFreeDepth").GetUlong();
            size_t curr = pending_frees;

            pool_metrics.push_back(non_paged_pool_metrics);
        }

        

        for (size_t i = 0; i < paged_pool_count; i++)
        {
            ExtRemoteTyped paged_pool("(nt!_POOL_DESCRIPTOR*)@$extin", paged_pool_addr + i * 0x1140);

            POOL_METRICS paged_pool_metrics = { 0, };
            paged_pool_metrics._pool_addr = paged_pool_addr + i * 0x1140;
            paged_pool_metrics._pool_start = paged_pool_start;
            paged_pool_metrics._pool_end = paged_pool_end;
            paged_pool_metrics._pool_index = paged_pool.Field("PoolIndex").GetUlong();
            paged_pool_metrics._pool_type = paged_pool.Field("PoolType").GetUlong();
            paged_pool_metrics._total_bytes = paged_pool.Field("BytesAllocated").GetUlong64();
            paged_pool_metrics._total_pages = paged_pool.Field("PagesAllocated").GetUlong64();
            paged_pool_metrics._total_big_pages = paged_pool.Field("BigPagesAllocated").GetUlong64();
            stringstream ss;
            ss << "Paged Pool " << i;
            paged_pool_metrics._comment = ss.str();

            size_t pending_frees = paged_pool.Field("PendingFrees.Next").GetUlong64();
            size_t pending_free_depth = paged_pool.Field("PendingFreeDepth").GetUlong();
            size_t curr = pending_frees;

            pool_metrics.push_back(paged_pool_metrics);
        }

        

        
        ofstream ss(R"(E:\pool_range.txt)", ios::out | ios::trunc);
        for (auto& pool_info : pool_metrics)
        {
            ss << hex << showbase
                << "\n" << string(0x40, '*') << "\n"
                << setw(20) << "Paged Pool Metrics :" << pool_info._pool_addr << "\n"
                << setw(20) << "comment :" << pool_info._comment << "\n"
                << setw(20) << "pool index :" << pool_info._pool_index << "\n"
                << setw(20) << "total bytes :" << pool_info._total_bytes << "(" << pool_info._total_bytes / 1024 / 1024 << " MB)\n"
                << setw(20) << "total pages :" << pool_info._total_pages << "\n"
                << setw(20) << "range start :" << pool_info._pool_start << "\n"
                << setw(20) << "range end :" << pool_info._pool_end << "\n"
                << setw(20) << "total big pages :" << pool_info._total_big_pages << "\n\n";

            ss << setw(20) << "pending frees :" << "\n";
            for (auto& pending : pool_info._pending_frees)
            {
                ss << "\t" << pending;
            }
            ss << endl;

            ss << setw(20) << "free lists :" << "\n";

            for (auto& free_list : pool_info._free_lists)
            {
                ss << "[" << free_list.first * 0x10 << "]\n";
                for (auto& item : free_list.second)
                {
                    ss << "\t" << item;
                }
                ss << "\n";
            }
            ss << endl;
        }
    }
    FILTER_CATCH;
}

void CTokenExt::traverse_linked_list(size_t head)
{
    try
    {
        size_t curr = head;
        do
        {
            curr = read<size_t>(head);



        } while (curr != head);
    }
    FILTER_CATCH;
}

void CTokenExt::dump_trap_frame(size_t thread_addr)
{
    try
    {
        ExtRemoteTyped thread("(nt!_KTHREAD*)@$extin", thread_addr);
        size_t trap_frame_addr = thread.Field("TrapFrame").GetUlongPtr();

        Out("Trap Frame: 0x%I64x\n", trap_frame_addr);
        stringstream cmd;
        cmd << "dt nt!_KTRAP_FRAME ";
        cmd << hex << showbase << trap_frame_addr;
        x(cmd.str());
    }
    FILTER_CATCH;
}

string CTokenExt::dump_sid(size_t sid_addr)
{
    if (sid_addr == 0)
        return "";
    try
    {
        uint8_t version = read<uint8_t>(sid_addr);
        uint8_t sub_count = read<uint8_t>(sid_addr + 1);
        stringstream ss;
        if (version == 1 && sub_count <= 0x0F)
        {                           
            ss << "S-1-";
            uint8_t auth = read<uint8_t>(sid_addr + 7);
            ss << dec << uint32_t(auth) << "-";
            for (size_t i = 0; i < sub_count; i++)
            {
                uint32_t sub = read<uint32_t>(sid_addr + 4*(i+2));
                if (sub < 0xFFFF)
                    ss << dec << sub;
                else
                    ss << showbase << hex << sub;

                if (i != sub_count - 1)
                    ss << "-";
            }
        }   
        string comment = getWellKnownAccount(ss.str());
        if (!comment.empty())
            ss << " [" << comment << "]";
        return ss.str();
    }
    FILTER_CATCH;

    return "";
}

string CTokenExt::dump_guid(size_t addr)
{
    try
    {
        uint32_t first = read<uint32_t>(addr);
        uint16_t second = read<uint16_t>(addr + 0x04);
        uint16_t third = read<uint16_t>(addr + 0x06);
        uint8_t forth = read<uint8_t>(addr + 0x08);
        uint8_t fifth = read<uint8_t>(addr + 0x09);

        stringstream ss;
        ss << hex << noshowbase << setfill('0')
            << "{"
            << setw(8) << first << "-"
            << setw(4) << second << "-"
            << setw(4) << third << "-"
            << setw(2) << (uint16_t)forth
            << setw(2) << (uint16_t)fifth << "-";

        for (size_t i = 0; i < 0x06; i++)
            ss << setw(2) << (uint16_t)read<uint8_t>(addr + 0x0A + i);

        ss << "}";

        return ss.str();
    }
    FILTER_CATCH;

    return "";
}

string CTokenExt::dump_sid_attr_array(size_t sid_addr, size_t count)
{
    stringstream ss;
    try
    {
        for (size_t i = 0; i < count; i++)
        {
            ExtRemoteTyped entry("(nt!_SID_AND_ATTRIBUTES*)@$extin", sid_addr + i * 0x10);
            ss << showbase << hex << setw(16) << sid_addr + i * 0x10 << " ";
            ss << showbase << hex << setw(16) << entry.Field("Attributes").GetUlong() << " [" << getGroupsAttrText(entry.Field("Attributes").GetUlong(), true) << "] ";
            ss << dump_sid(entry.Field("Sid").GetLongPtr()).c_str() << "\n";              
        }
    }
    FILTER_CATCH;
    return ss.str();
}

string CTokenExt::get_sid_attr_array_item(size_t sid_addr, size_t count, size_t index)
{
    stringstream ss;
    try
    {
        for (size_t i = 0; i < count; i++)
        {
            if (i != index)
                continue;
            ExtRemoteTyped entry("(nt!_SID_AND_ATTRIBUTES*)@$extin", sid_addr + i * 0x10);
            ss << dump_sid(entry.Field("Sid").GetLongPtr()).c_str();
        }
    }
    FILTER_CATCH;
    return ss.str();
}

string CTokenExt::dump_sid_attr_hash(size_t addr)
{
    stringstream ss;

    try
    {
        ExtRemoteTyped hash("(nt!_SID_AND_ATTRIBUTES_HASH*)@$extin", addr);
        ss << dump_sid_attr_array(hash.Field("SidAttr").GetLongPtr(), hash.Field("SidCount").GetUlong()) << "\n";
        for (size_t i = 0; i < 0x20; i++)
        {
            if (i % 0x08 == 0)
                ss << "\n";
            ss << showbase << hex << setw(16) << read<size_t>(addr + hash.GetFieldOffset("Hash") + i * 0x08) << " ";             
        }
    }
    FILTER_CATCH;

    return ss.str();
}

string CTokenExt::get_sid_attr_hash_item(size_t addr, size_t index)
{
    stringstream ss;

    try
    {
        ExtRemoteTyped hash("(nt!_SID_AND_ATTRIBUTES_HASH*)@$extin", addr);
        ss << get_sid_attr_array_item(hash.Field("SidAttr").GetLongPtr(), hash.Field("SidCount").GetUlong(), index);
    }
    FILTER_CATCH;

    return ss.str();
}

bool CTokenExt::check()
{
    initialize();
    //if (IsUserMode())
    //{
    //    Err("tokenext extension can only work in kernel-mode\n");
    //    return false;
    //}

    if (!IsCurMachine64())
    {
        Err("tokenext only support 64bit now\n");
        return false;
    }

    return true;
}

void CTokenExt::obj(void)
{
    if (!check())
        return;

    auto param1 = GetUnnamedArgU64(0);
    if (0 == param1)
        m_System->GetCurrentProcessDataOffset(&param1);

    dump_obj(param1);
}

void CTokenExt::gobj(void)
{
    if (!check())
        return;

    size_t root_obj_dir_addr = readDbgDataAddr(DEBUG_DATA_ObpRootDirectoryObjectAddr);
    if (root_obj_dir_addr == 0)
        return;

    try
    {
        dump_obj_dir(read<size_t>(root_obj_dir_addr), 0, true);
    }
    FILTER_CATCH; 
} 

void CTokenExt::dump_ps_flags(size_t addr)
{
	try
	{
		stringstream ss;

		ExtRemoteTyped ps("(nt!_EPROCESS*)@$extin", addr);

		uint32_t flags = ps.Field("Flags").GetUlong();
		uint32_t flags2 = ps.Field("Flags2").GetUlong();
		uint32_t flags3 = ps.Field("Flags3").GetUlong();

		PS_FLAGS ps_flags(flags);
		PS_FLAGS2 ps_flags2(flags2);
		PS_FLAGS3 ps_flags3(flags3);

		dump_process(addr);

		ss << string(50, '-') << setw(12) << "Flags: [ " << hex << showbase << setw(10) << flags << " ]" << string(50, '-') << endl
			<< ps_flags.str() << endl;
		ss << string(50, '-') << setw(12) << "Flags2: [" << hex << showbase << setw(10) << flags2 << " ]" << string(50, '-') << endl 
			<< ps_flags2.str() << endl;
		ss << string(50, '-') << setw(12) << "Flags3: [" << hex << showbase << setw(10) << flags3 << " ]" << string(50, '-') << endl 
			<< ps_flags3.str() << endl;

		Out(ss.str().c_str());			
	}
	FILTER_CATCH;
}

void CTokenExt::pses(void)
{
    //size_t list_head = readDbgDataAddr(DEBUG_DATA_PsActiveProcessHeadAddr);
    try
    {
        ExtRemoteTypedList pses_list = ExtNtOsInformation::GetKernelProcessList();
		
        for (pses_list.StartHead(); pses_list.HasNode(); pses_list.Next())
        {
            /*m_Control->ControlledOutput(DEBUG_OUTCTL_ALL_OTHER_CLIENTS
                , DEBUG_OUTPUT_NORMAL, "ps\n");*/
			dump_process(pses_list.GetNodeOffset());
        }
    }FILTER_CATCH;
}

void CTokenExt::dump_types()
{
    try
    {
        size_t types_table = getSymbolAddr("nt!ObpObjectTypes");

        for (size_t i = 0; i < 0xFF; i++)
        {
            size_t type_addr = read<size_t>(types_table + i * sizeof(size_t));

            if (type_addr == 0)
                break;

            ExtRemoteTyped type("(nt!_OBJECT_TYPE*)@$extin", type_addr);
            wstring name = readUnicodeString(type_addr + type.GetFieldOffset("Name"));
            uint32_t num_objects = type.Field("TotalNumberOfObjects").GetUlong();
            uint32_t num_handles = type.Field("TotalNumberOfHandles").GetUlong();
            uint32_t valid_access_mask = type.Field("TypeInfo.ValidAccessMask").GetUlong();
            static const char* routines[] {
                    "DumpProcedure",       
                    "OpenProcedure",     
                    "CloseProcedure", 
                    "DeleteProcedure",    
                    "ParseProcedure",   
                    "SecurityProcedure",
                    "QueryNameProcedure", 
                    "OkayToCloseProcedure"
                };

            Out(L"%02X objs: 0x%08x, handles: 0x%08x  0x%08x %s\n", i, num_objects, num_handles, valid_access_mask, name.c_str());  
            Out("Routines:\n");
            for (auto& routine : routines)
            {
                string field = "TypeInfo.";
                field += routine;
                Out("%20s : 0x%I64x\n", routine, type.Field(field.c_str()).GetUlongPtr());
            }
        }
    }
    FILTER_CATCH;
}

size_t CTokenExt::curr_proc()
{
    size_t curr_proc_addr = 0;
    m_System->GetCurrentProcessDataOffset(&curr_proc_addr);
    return curr_proc_addr;
}

size_t CTokenExt::curr_thread()
{
    size_t curr_thread_addr = 0;
    m_System->GetCurrentThreadDataOffset(&curr_thread_addr);
    return curr_thread_addr;
}

size_t CTokenExt::curr_tid()
{
    try
    {
        ExtRemoteTyped curr_ethread("(nt!_ETHREAD*)@$extin", curr_thread());
        return curr_ethread.Field("Cid.UniqueThread").GetUlong64();
    }
    FILTER_CATCH;

    return 0;
}

size_t CTokenExt::curr_token()
{
    try
    {
        ExtRemoteTyped ps("(nt!_EPROCESS*)@$extin", curr_proc());
        size_t token_addr = ps.Field("Token.Object").GetUlong64();

        return token_addr & 0xFFFFFFFFFFFFFFF0;
    }
    FILTER_CATCH;

    return 0;
}


size_t CTokenExt::getIntArg(vector<string>& args, size_t idx, size_t default_val)
{
    if (idx < 0 || idx >= args.size())
        return default_val;

    string arg = args[idx];

    if (arg.size() == 17 && arg[8] == '`')
    {
        for (size_t i = 8; i < 17; i++)
            arg[i] = arg[i + 1];
        arg.resize(16);
    }
    else if (arg.size() == 19 && arg[10] == '`' && arg[0] == '0' && (arg[1] == 'x' || arg[1] == 'X'))
    {
        for (size_t i = 10; i < 19; i++)
            arg[i] = arg[i + 1];
        arg.resize(18);
    }

    try
    {
        size_t val = strtoull(arg.c_str(), nullptr, 16);
        if (val == 0)
            return default_val;

        return val;
    }
    catch (exception& e)
    {
        Err("Invalid conversion!\n");
    }

    return default_val;
}

void CTokenExt::types(void)
{
    dump_types();
}

void CTokenExt::lmu(void)
{
    dump_user_modules();
} 

void CTokenExt::lmk(void)
{
    dump_kernel_modules();
} 

void CTokenExt::dbgdata(void)
{
    if (!check())
        return;

    Out("Debugger Data:\n");
    Out("%30s 0x%0I64x\n", "kernel base",
        readDbgDataAddr(DEBUG_DATA_KernBase));

    Out("%30s 0x%0I64x\n", "BreakpointWithStatusInstruction.",
        readDbgDataAddr(DEBUG_DATA_BreakpointWithStatusAddr));

    Out("%30s 0x%0I64x\n", "KiCallUserMode.",
        readDbgDataAddr(DEBUG_DATA_KiCallUserModeAddr));

    Out("%30s 0x%0I64x\n", "KeUserCallbackDispatcher.",
        readDbgDataAddr(DEBUG_DATA_KeUserCallbackDispatcherAddr));

    Out("%30s 0x%0I64x\n", "PsLoadedModuleList.",
        readDbgDataAddr(DEBUG_DATA_PsLoadedModuleListAddr));

    Out("%30s 0x%0I64x\n", "PsActiveProcessHead.",
        readDbgDataAddr(DEBUG_DATA_PsActiveProcessHeadAddr));

    Out("%30s 0x%0I64x\n", "PspCidTable.",
        readDbgDataAddr(DEBUG_DATA_PspCidTableAddr));

    Out("%30s 0x%0I64x\n", "ExpSystemResourcesList.",
        readDbgDataAddr(DEBUG_DATA_ExpSystemResourcesListAddr));

    Out("%30s 0x%0I64x\n", "ExpPagedPoolDescriptor.",
        readDbgDataAddr(DEBUG_DATA_ExpPagedPoolDescriptorAddr));

    Out("%30s 0x%0I64x\n", "ExpNumberOfPagedPools.",
        readDbgDataAddr(DEBUG_DATA_ExpNumberOfPagedPoolsAddr));

    Out("%30s 0x%0I64x\n", "KeTimeIncrement.",
        readDbgDataAddr(DEBUG_DATA_KeTimeIncrementAddr));

    Out("%30s 0x%0I64x\n", "KeBugCheckCallbackListHead.",
        readDbgDataAddr(DEBUG_DATA_KeBugCheckCallbackListHeadAddr));

    Out("%30s 0x%0I64x\n", "KiBugCheckData.",
        readDbgDataAddr(DEBUG_DATA_KiBugcheckDataAddr));

    Out("%30s 0x%0I64x\n", "IopErrorLogListHead.",
        readDbgDataAddr(DEBUG_DATA_IopErrorLogListHeadAddr));

    Out("%30s 0x%0I64x\n", "ObpRootDirectoryObject.",
        readDbgDataAddr(DEBUG_DATA_ObpRootDirectoryObjectAddr));

    Out("%30s 0x%0I64x\n", "ObpTypeObjectType.",
        readDbgDataAddr(DEBUG_DATA_ObpTypeObjectTypeAddr));

    Out("%30s 0x%0I64x\n", "MmSystemCacheStart.",
        readDbgDataAddr(DEBUG_DATA_MmSystemCacheStartAddr));

    Out("%30s 0x%0I64x\n", "MmSystemCacheEnd.",
        readDbgDataAddr(DEBUG_DATA_MmSystemCacheEndAddr));

    Out("%30s 0x%0I64x\n", "MmSystemCacheWs.",
        readDbgDataAddr(DEBUG_DATA_MmSystemCacheWsAddr));

    Out("%30s 0x%0I64x\n", "MmPfnDatabase.",
        readDbgDataAddr(DEBUG_DATA_MmPfnDatabaseAddr));

    Out("%30s 0x%0I64x\n", "MmSystemPtesStart.",
        readDbgDataAddr(DEBUG_DATA_MmSystemPtesStartAddr));

    Out("%30s 0x%0I64x\n", "MmSystemPtesEnd.",
        readDbgDataAddr(DEBUG_DATA_MmSystemPtesEndAddr));

    Out("%30s 0x%0I64x\n", "MmSubsectionBase.",
        readDbgDataAddr(DEBUG_DATA_MmSubsectionBaseAddr));

    Out("%30s 0x%0I64x\n", "MmNumberOfPagingFiles.",
        readDbgDataAddr(DEBUG_DATA_MmNumberOfPagingFilesAddr));

    Out("%30s 0x%0I64x\n", "MmLowestPhysicalPage.",
        readDbgDataAddr(DEBUG_DATA_MmLowestPhysicalPageAddr));

    Out("%30s 0x%0I64x\n", "MmHighestPhysicalPage.",
        readDbgDataAddr(DEBUG_DATA_MmHighestPhysicalPageAddr));

    Out("%30s 0x%0I64x\n", "MmNumberOfPhysicalPages.",
        readDbgDataAddr(DEBUG_DATA_MmNumberOfPhysicalPagesAddr));

    Out("%30s 0x%0I64x\n", "MmMaximumNonPagedPoolInBytes.",
        readDbgDataAddr(DEBUG_DATA_MmMaximumNonPagedPoolInBytesAddr));

    Out("%30s 0x%0I64x\n", "MmNonPagedSystemStart.",
        readDbgDataAddr(DEBUG_DATA_MmNonPagedSystemStartAddr));

    Out("%30s 0x%0I64x\n", "MmNonPagedPoolStart.",
        readDbgDataAddr(DEBUG_DATA_MmNonPagedPoolStartAddr));

    Out("%30s 0x%0I64x\n", "MmNonPagedPoolEnd.",
        readDbgDataAddr(DEBUG_DATA_MmNonPagedPoolEndAddr));

    Out("%30s 0x%0I64x\n", "MmPagedPoolStart.",
        readDbgDataAddr(DEBUG_DATA_MmPagedPoolStartAddr));

    Out("%30s 0x%0I64x\n", "MmPagedPoolEnd.",
        readDbgDataAddr(DEBUG_DATA_MmPagedPoolEndAddr));

    Out("%30s 0x%0I64x\n", "MmPagedPoolInfo.",
        readDbgDataAddr(DEBUG_DATA_MmPagedPoolInformationAddr));

    Out("%30s 0x%0I64x\n", "MmSizeOfPagedPoolInBytes.",
        readDbgDataAddr(DEBUG_DATA_MmSizeOfPagedPoolInBytesAddr));

    Out("%30s 0x%0I64x\n", "MmTotalCommitLimit.",
        readDbgDataAddr(DEBUG_DATA_MmTotalCommitLimitAddr));

    Out("%30s 0x%0I64x\n", "MmTotalCommittedPages.",
        readDbgDataAddr(DEBUG_DATA_MmTotalCommittedPagesAddr));

    Out("%30s 0x%0I64x\n", "MmSharedCommit.",
        readDbgDataAddr(DEBUG_DATA_MmSharedCommitAddr));

    Out("%30s 0x%0I64x\n", "MmDriverCommit.",
        readDbgDataAddr(DEBUG_DATA_MmDriverCommitAddr));

    Out("%30s 0x%0I64x\n", "MmProcessCommit.",
        readDbgDataAddr(DEBUG_DATA_MmProcessCommitAddr));

    Out("%30s 0x%0I64x\n", "MmPagedPoolCommit.",
        readDbgDataAddr(DEBUG_DATA_MmPagedPoolCommitAddr));

    Out("%30s 0x%0I64x\n", "MmExtendedCommit..",
        readDbgDataAddr(DEBUG_DATA_MmExtendedCommitAddr));

    Out("%30s 0x%0I64x\n", "MmZeroedPageListHead.",
        readDbgDataAddr(DEBUG_DATA_MmZeroedPageListHeadAddr));

    Out("%30s 0x%0I64x\n", "MmFreePageListHead.",
        readDbgDataAddr(DEBUG_DATA_MmFreePageListHeadAddr));

    Out("%30s 0x%0I64x\n", "MmStandbyPageListHead.",
        readDbgDataAddr(DEBUG_DATA_MmStandbyPageListHeadAddr));

    Out("%30s 0x%0I64x\n", "MmModifiedPageListHead.",
        readDbgDataAddr(DEBUG_DATA_MmModifiedPageListHeadAddr));

    Out("%30s 0x%0I64x\n", "MmModifiedNoWritePageListHead.",
        readDbgDataAddr(DEBUG_DATA_MmModifiedNoWritePageListHeadAddr));

    Out("%30s 0x%0I64x\n", "MmAvailablePages.",
        readDbgDataAddr(DEBUG_DATA_MmAvailablePagesAddr));

    Out("%30s 0x%0I64x\n", "MmResidentAvailablePages.",
        readDbgDataAddr(DEBUG_DATA_MmResidentAvailablePagesAddr));

    Out("%30s 0x%0I64x\n", "PoolTrackTable.",
        readDbgDataAddr(DEBUG_DATA_PoolTrackTableAddr));

    Out("%30s 0x%0I64x\n", "NonPagedPoolDescriptor.",
        readDbgDataAddr(DEBUG_DATA_NonPagedPoolDescriptorAddr));

    Out("%30s 0x%0I64x\n", "MmHighestUserAddress.",
        readDbgDataAddr(DEBUG_DATA_MmHighestUserAddressAddr));

    Out("%30s 0x%0I64x\n", "MmSystemRangeStart.",
        readDbgDataAddr(DEBUG_DATA_MmSystemRangeStartAddr));

    Out("%30s 0x%0I64x\n", "MmUserProbeAddress.",
        readDbgDataAddr(DEBUG_DATA_MmUserProbeAddressAddr));

    Out("%30s 0x%0I64x\n", "KdPrintDefaultCircularBuffer.",
        readDbgDataAddr(DEBUG_DATA_KdPrintCircularBufferAddr));

    Out("%30s 0x%0I64x\n", "KdPrintDefaultCircularBuffer",
        readDbgDataAddr(DEBUG_DATA_KdPrintCircularBufferEndAddr));

    Out("%30s 0x%0I64x\n", "KdPrintWritePointer.",
        readDbgDataAddr(DEBUG_DATA_KdPrintWritePointerAddr));

    Out("%30s 0x%0I64x\n", "KdPrintRolloverCount.",
        readDbgDataAddr(DEBUG_DATA_KdPrintRolloverCountAddr));

    Out("%30s 0x%0I64x\n", "MmLoadedUserImageList.",
        readDbgDataAddr(DEBUG_DATA_MmLoadedUserImageListAddr));

}

ExtCommandDesc g_handles_desc(
    "handles",
    (ExtCommandMethod)&CTokenExt::handles,
    "Output the Windows 10 handles list of the target process",
    "{;e,o,d=0;eprocess;_EPROCESS address}");

extern "C"
HRESULT
CALLBACK
handles(
    __in        PDEBUG_CLIENT   client,
    __in_opt    PCSTR           args)
{
    if (!g_Ext.IsSet())
    {
        return E_UNEXPECTED;
    }
    return g_Ext->CallCommand(&g_handles_desc, client, args);
}

ExtCommandDesc g_dbgdata_desc(
    "dbgdata",
    (ExtCommandMethod)&CTokenExt::dbgdata,
    "Output the Debugger Data fields",
    "");

extern "C"
HRESULT
CALLBACK
dbgdata(
    __in        PDEBUG_CLIENT   client,
    __in_opt    PCSTR           args)
{
    if (!g_Ext.IsSet())
    {
        return E_UNEXPECTED;
    }
    return g_Ext->CallCommand(&g_dbgdata_desc, client, args);
}

ExtCommandDesc g_gobj_desc(
    "gobj",
    (ExtCommandMethod)&CTokenExt::gobj,
    "Dump objects from root object directory",
    "");

extern "C"
HRESULT
CALLBACK
gobj(
    __in        PDEBUG_CLIENT   client,
    __in_opt    PCSTR           args)
{
    if (!g_Ext.IsSet())
    {
        return E_UNEXPECTED;
    }
    return g_Ext->CallCommand(&g_gobj_desc, client, args);
}

ExtCommandDesc g_lmk_desc(
    "lmk",
    (ExtCommandMethod)&CTokenExt::lmk,
    "list kernel-mode modules",
    "");

extern "C"
HRESULT
CALLBACK
lmk(
    __in        PDEBUG_CLIENT   client,
    __in_opt    PCSTR           args)
{
    if (!g_Ext.IsSet())
    {
        return E_UNEXPECTED;
    }
    return g_Ext->CallCommand(&g_lmk_desc, client, args);
}

ExtCommandDesc g_pses_desc(
    "pses",
    (ExtCommandMethod)&CTokenExt::pses,
    "Dump all active processes",
    "");

extern "C"
HRESULT
CALLBACK
pses(
    __in        PDEBUG_CLIENT   client,
    __in_opt    PCSTR           args)
{
    if (!g_Ext.IsSet())
    {
        return E_UNEXPECTED;
    }
    return g_Ext->CallCommand(&g_pses_desc, client, args);
}

ExtCommandDesc g_types_desc(
    "types",
    (ExtCommandMethod)&CTokenExt::types,
    "list object types",
    "");

extern "C"
HRESULT
CALLBACK
types(
    __in        PDEBUG_CLIENT   client,
    __in_opt    PCSTR           args)
{
    if (!g_Ext.IsSet())
    {
        return E_UNEXPECTED;
    }
    return g_Ext->CallCommand(&g_types_desc, client, args);
}

ExtCommandDesc g_obj_desc(
    "obj",
    (ExtCommandMethod)&CTokenExt::obj,
    "Object detailed information",
    "{;e,o,d=0;object;_OBJECT_HEADER address}");

extern "C"
HRESULT
CALLBACK
obj(
    __in        PDEBUG_CLIENT   client,
    __in_opt    PCSTR           args)
{
    if (!g_Ext.IsSet())
    {
        return E_UNEXPECTED;
    }
    return g_Ext->CallCommand(&g_obj_desc, client, args);
}

ExtCommandDesc g_dk_desc(
    "dk",
    (ExtCommandMethod)&CTokenExt::dk,
    "Customized command line parse entry",
    "{{custom}}");

extern "C"
HRESULT
CALLBACK
dk(
    __in        PDEBUG_CLIENT   client,
    __in_opt    PCSTR           args)
{
    if (!g_Ext.IsSet())
    {
        return E_UNEXPECTED;
    }
    return g_Ext->CallCommand(&g_dk_desc, client, args);
}
