#include "TokenExt.h" 

#define FILTER_CATCH \
    catch (ExtException& e)     \
    {                            \
        Err("%s %s %d\n", __FILE__, __FUNCTION__, __LINE__);       \
        /*ThrowRemote(e.GetStatus(), e.GetMessageA());      \ 
    */}                          \
    catch (exception& e)        \
    {           \
        Err("%s %s %d\n", __FILE__, __FUNCTION__, __LINE__);       \
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

void CTokenExt::dk(void)
{
    if (!check())
        return;

    try
    {
        reset_options();

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

            for (size_t i = 1; i < args.size(); i++)
            {
                if (args[i] == "/f")
                    m_dk_options.m_detail = true;
                else if (args[i] == "/po")
                    m_dk_options.m_process_object = true;
                else if (args[i] == "/to")
                    m_dk_options.m_token_object = true;
                else if (args[i] == "/r")
                    m_dk_options.m_recursive = true;
                else if (args[i] == "/o")
                    m_dk_options.m_object = true;
                else if (args[i] == "/ht")
                    m_dk_options.m_handle_table = true;
                else if (args[i] == "/token")
                    m_dk_options.m_token = true;
                else if (args[i] == "/link")
                    m_dk_options.m_linked_token = true;
                else if (args[i] == "/threads")
                    m_dk_options.m_threads = true;
            }

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
            else if (cmd == "types")
            {
                types();
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

void CTokenExt::dump_obj(size_t obj_addr)
{
    try
    {
        ExtRemoteTyped obj_hdr("(nt!_OBJECT_HEADER*)@$extin", obj_addr);
        //obj_hdr.OutFullValue();

        uint8_t real_index = realIndex(obj_hdr.Field("TypeIndex").GetUchar(), obj_addr);
        size_t sdr_addr = obj_hdr.Field("SecurityDescriptor").GetLongPtr() & 0xFFFFFFFFFFFFFFF0;

        wstring obj_name = dump_obj_name(obj_addr);
        wstring type_name = getTypeName(real_index);

        if (obj_name.empty() && type_name == L"File")
            Out(L"0x%0I64x 0x%02x %20s %s\n", obj_addr, real_index, type_name.c_str(), dump_file_name(obj_addr+0x30).c_str());
        else
            Out(L"0x%0I64x 0x%02x %20s %s\n", obj_addr, real_index, type_name.c_str(), obj_name.c_str());

        if (sdr_addr != 0)
            dump_sdr(sdr_addr);         

    }
    FILTER_CATCH;
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
        Out("0x%0I64x %8d %02x(%02x, %02x) %s\n", process_addr, pid, protection, signing_level, dll_signing_level, name);

        size_t token_addr = ps.Field("Token.Object").GetUlong64();

        if (m_dk_options.m_detail || m_dk_options.m_token)
            dump_token(token_addr & 0xFFFFFFFFFFFFFFF0);

        if (m_dk_options.m_detail || m_dk_options.m_process_object)
            dump_obj(process_addr - 0x30);

        if (m_dk_options.m_detail || m_dk_options.m_token_object)
            dump_obj((token_addr & 0xFFFFFFFFFFFFFFF0) - 0x30);

        if (m_dk_options.m_detail || m_dk_options.m_handle_table)
            dump_process_handle_table(process_addr);

        if (m_dk_options.m_detail || m_dk_options.m_handle_table || m_dk_options.m_token || m_dk_options.m_process_object || m_dk_options.m_token_object)
            Out("\n%s\n\n", string(50, '#').c_str());

        if (m_dk_options.m_detail || m_dk_options.m_threads)
            dump_process_threads(process_addr);
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
    
    Out("HandleTable : 0x%I64x, count: 0x%08x, level: 0x%08x\n", handle_table_addr, handle_count, level);
    Out("%-18s %-18s %-10s %-10s %-4s %-20s %s\n", "object_table_entry", "object_header_addr", "access", "handle", "type", "type_name", "object_name");
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

                    if (obj_name.empty() && type_name == L"File")
                        Out(L"0x%0I64x 0x%0I64x 0x%08x 0x%08x 0x%02x %20s %s\n", entry, addr, access, handle_value, real_index, type_name.c_str(), dump_file_name(addr+0x30).c_str());
                    else
                        Out(L"0x%0I64x 0x%0I64x 0x%08x 0x%08x 0x%02x %20s %s\n", entry, addr, access, handle_value, real_index, type_name.c_str(), obj_name.c_str());

                    if (m_dk_options.m_detail || m_dk_options.m_object)
                        dump_obj(addr);
                    if (type_name == L"Directory" && (m_dk_options.m_detail || m_dk_options.m_recursive))
                        dump_obj_dir(addr);
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

void CTokenExt::dump_sdr(size_t sd_addr)
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
                Out("--Sacl:\n%s\n", dump_acl(sd_addr + sacl_off).c_str());
            uint32_t dacl_off = sdr.Field("Dacl").GetUlong();
            if (dacl_off != 0)
                Out("--Dacl:\n%s\n", dump_acl(sd_addr + dacl_off).c_str());
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
        
        if (m_dk_options.m_detail || m_dk_options.m_token)
            dump_token(session.Field("Token").GetUlongPtr() & 0xFFFFFFFFFFFFFFF0);
    }
    FILTER_CATCH
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
        for (threads_list.StartHead(); threads_list.HasNode(); threads_list.Next())
        {
            auto thread = threads_list.GetTypedNode();
            size_t thread_addr = threads_list.GetNodeOffset();

            size_t unique_process = thread.Field("Cid.UniqueProcess").GetUlongPtr();
            size_t unique_thread = thread.Field("Cid.UniqueThread").GetUlongPtr();

            size_t teb_addr = thread.Field("Tcb.Teb").GetUlongPtr();

            size_t thread_token_addr = get_thread_token(thread_addr);

            //size_t start_addr = thread.Field("Win32StartAddress").GetUlongPtr();

            //string start_func_name = getAddrSymbol(start_addr);

            Out("Thread: 0x%I64x, Cid: %x.%x, Teb: 0x%I64x", thread_addr, unique_process, unique_thread, teb_addr);
            if (thread_token_addr != 0)
                Out(" Token: 0x%I64x", thread_token_addr);
            Out("\n");
        }
    }
    FILTER_CATCH;
}

size_t CTokenExt::get_thread_token(size_t thread_addr)
{
    size_t ret = 0;
    try
    {
        ExtRemoteTyped thread("(nt!_ETHREAD*)@$extin", thread_addr);
        bool impersonating = (thread.Field("CrossThreadFlags").GetUlong() & 8) != 0;
        if (impersonating)
            ret = thread.Field("ClientSecurity.ImpersonationToken").GetUlongPtr() & 0xFFFFFFFFFFFFFFF8;
    }
    FILTER_CATCH;
    return ret;
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

string CTokenExt::dump_acl(size_t acl_addr)
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
            ss << hex << setw(2) << setfill('0') << uint32_t(type) << " "
                << hex << setw(4) << setfill('0') << mask << " "
                << sid_str;
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

void 
CTokenExt::dump_obj_dir(
    size_t obj_hdr_addr, 
    size_t level, 
    bool recurse)
{
    if (obj_hdr_addr == 0)
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

        size_t obj_dir_addr = obj_hdr_addr + 0x30;
        if (obj_dir_addr == 0)
            return;

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
                    wstring type_name = getTypeName(realIndex(obj_hdr.Field("TypeIndex").GetUchar(), obj_addr - 0x30));
                    wstring tab(level*4, L' ');
                    tab += L"->";
                    if (type_name == L"File")
                        Out(L"%s%02x %20s %s\n", tab.c_str(), i, type_name.c_str(), dump_file_name(obj_addr - 0x30).c_str());
                    else
                        Out(L"%s%02x %20s %s\n", tab.c_str(), i, type_name.c_str(), dump_obj_name(obj_addr - 0x30).c_str());
                    dump_obj(obj_addr-0x30);

                    if (recurse && type_name == L"Directory")
                        dump_obj_dir(obj_addr-0x30, level+1);
                    

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
        text += "PsProtectedSignerNone]";
        break;
    case 0x10:
        text += "PsProtectedSignerAuthenticode]";
        break;
    case 0x20:
        text += "PsProtectedSignerCodeGen]";
        break;
    case 0x30:
        text += "PsProtectedSignerAntiMalware]";
        break;
    case 0x40:
        text += "PsProtectedSignerLsa]";
        break;
    case 0x50:
        text += "PsProtectedSignerWindows]";
        break;
    case 0x60:
        text += "PsProtectedSignerTcb]";
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
        return getIntegrityLevel(dump_sid(il_sid_addr));
    }
    FILTER_CATCH;
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

bool CTokenExt::check()
{
    initialize();
    if (IsUserMode())
    {
        Err("tokenext extension can only work in kernel-mode\n");
        return false;
    }

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

void CTokenExt::pses(void)
{
    //size_t list_head = readDbgDataAddr(DEBUG_DATA_PsActiveProcessHeadAddr);
    ExtRemoteTypedList pses_list = ExtNtOsInformation::GetKernelProcessList();

    for (pses_list.StartHead(); pses_list.HasNode(); pses_list.Next())
    {
        ExtRemoteTyped ps = pses_list.GetTypedNode();
        size_t name_addr = pses_list.GetNodeOffset() + ps.GetFieldOffset("ImageFileName");
        char name[16] = { 0, };
        m_Data->ReadVirtual(name_addr, name, 15, NULL);
        size_t pid = ps.Field("UniqueProcessId").GetUlongPtr();  
        uint8_t protection = read<uint8_t>(pses_list.GetNodeOffset() + ps.GetFieldOffset("Protection")); 
        uint8_t signing_level = read<uint8_t>(pses_list.GetNodeOffset() + ps.GetFieldOffset("SignatureLevel"));
        uint8_t dll_signing_level = read<uint8_t>(pses_list.GetNodeOffset() + ps.GetFieldOffset("SectionSignatureLevel"));
        size_t token_addr = ps.Field("Token.Object").GetUlong64();


        Out("0x%0I64x %8d %02x(%02x, %02x) %20s %40s %50s\n", 
            pses_list.GetNodeOffset(), pid, protection, signing_level, dll_signing_level, name, 
            getProtectionText(protection).c_str(),
            getTokenIL(token_addr & 0xFFFFFFFFFFFFFFF0).c_str());
        

        if (m_dk_options.m_detail || m_dk_options.m_token)
            dump_token(token_addr & 0xFFFFFFFFFFFFFFF0); 

        if (m_dk_options.m_detail || m_dk_options.m_process_object)
            dump_obj(pses_list.GetNodeOffset() - 0x30);

        if (m_dk_options.m_detail || m_dk_options.m_token_object)
            dump_obj((token_addr & 0xFFFFFFFFFFFFFFF0) - 0x30);

        if (m_dk_options.m_detail || m_dk_options.m_handle_table)
            dump_process_handle_table(pses_list.GetNodeOffset());

        if (m_dk_options.m_detail || m_dk_options.m_handle_table || m_dk_options.m_token || m_dk_options.m_process_object || m_dk_options.m_token_object)
            Out("\n%s\n\n", string(50, '#').c_str());

        if (m_dk_options.m_detail || m_dk_options.m_threads)
            dump_process_threads(pses_list.GetNodeOffset());
    }
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