#pragma once
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <tuple>
#include <iomanip>
//#include <regex>
using namespace std;
#define EXT_CLASS CTokenExt 
#include "../inc/engextcpp10.hpp"
#include "HandleTable.h"

class CBitFieldAnalyzer
{
public:
    CBitFieldAnalyzer()
    {}

    CBitFieldAnalyzer(
        __in const map<uint32_t, const char*>& definitions
        )
    {
        for (auto it = definitions.begin();
        it != definitions.end();
            it++)
        {
            m_definitions[it->first] = it->second;
        }
    }

    CBitFieldAnalyzer(
        __in map<uint32_t, const char*>&& definitions
        )
        :m_definitions(move(definitions))
    {
    }

    string
        GetText(
            __in const uint32_t compound,
            __in bool pureText = false
            )
    {
        stringstream ss;
        if (!pureText)
            ss << "0x" << hex << noshowbase << setw(8) << setfill('0') << compound << "(";

        for (auto it = m_definitions.begin();
        it != m_definitions.end();
            it++)
        {
            if (it->first & compound)
                ss << it->second << ",";
        }

        if (!pureText)
            ss << ")";

        return ss.str();
    }

private:
    map<uint32_t, const char*> m_definitions;
};

struct cmp_str
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

class CDKOptions
{
public:
    bool m_detail;
    bool m_process_object;
    bool m_token_object;
    bool m_recursive;
    bool m_object;
    bool m_handle_table;
    bool m_token;
    bool m_linked_token;
    bool m_threads;
};

class CTokenExt 
    : public ExtExtension
{
public:
    CTokenExt();
    ~CTokenExt();

    void handles(void);

    void dbgdata(void);

    void obj(void);

    void gobj(void);

    void pses(void);

    void lmu(void);

    void lmk(void);

    void types(void);

    void dk(void);

private:
    size_t readDbgDataAddr(ULONG index);

    wstring getTypeName(size_t index);

    void initialize();

    void dump_user_modules();

    void dump_kernel_modules();

    uint8_t realIndex(size_t type_index, size_t obj_hdr_addr);

    void dump_obj(size_t obj_addr);

    void dump_process(size_t process_addr);

    void dump_handle_table(size_t handle_table_addr);

    void dump_kernel_handle_table();

    void dump_process_handle_table(size_t process_addr);

    void dump_sdr(size_t sd_addr);

    void dump_token(size_t token_addr);

    void dump_session(size_t session_addr);

    void dump_logon_sessions();

    void token_privilege_add(size_t token_addr, size_t bitmap);

    void dump_process_threads(size_t process_addr);

    size_t get_thread_token(size_t thread_addr);

    string dump_luid(size_t addr);

    string dump_sid(size_t sid_addr);

    string dump_sid_attr_array(size_t sid_addr, size_t count);

    string dump_sid_attr_hash(size_t addr);

    string dump_acl(size_t acl_addr);

    string dump_privilege(size_t addr);

    string dump_privileges_by_bitmap(size_t bitmap);

    string privilege_bit_to_text(size_t bit_offset);

    void dump_obj_dir(size_t obj_hdr_addr, size_t level = 0, bool recurse = false);

    size_t getSymbolAddr(const char* name);    

    string getAddrSymbol(size_t addr);

    string getProtectionText(uint8_t protection);

    string getTokenIL(size_t token_addr);

    bool valid_addr(size_t addr);

    wstring readUnicodeString(size_t addr);

    wstring dump_obj_name(size_t obj_hdr_addr);

    wstring dump_file_name(size_t file_obj_addr);

    wstring dump_sym_link(size_t addr);

    void dump_types();

    size_t curr_proc();

    size_t curr_token();

    void dump_usage();

    size_t getIntArg(vector<string>& args, size_t idx, size_t default_val);

    void reset_options()
    {
        m_dk_options.m_detail = false;
        m_dk_options.m_process_object = false;
        m_dk_options.m_token_object = false;
        m_dk_options.m_recursive = false;
        m_dk_options.m_object = false;
        m_dk_options.m_handle_table = false;
        m_dk_options.m_token = false;
        m_dk_options.m_linked_token = false;
        m_dk_options.m_threads = false;
    }

    static
    string
    getIntegrityLevel(
        __in const string& sidText
        )
    {
        auto it = s_integrity_level_texts.find(sidText.c_str());

        if (it != s_integrity_level_texts.end())
            return it->second;

        return "";
    }

    static
    string
    getTrustLabel(
        __in const string& sidText
        )
    {
        auto it = s_trust_label_texts.find(sidText.c_str());

        if (it != s_trust_label_texts.end())
            return it->second;

        return "";
    }

    static
    string
    getWellKnownAccount(
        __in const string& sidText
        )
    {
        auto it = s_wellknown_sids.find(sidText.c_str());

        if (it != s_wellknown_sids.end())
            return it->second;

        if (sidText.find("S-1-5-5-") == 0 && sidText.rfind("-") > 7)
            return "Logon Session";

        if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-500") == sidText.length() - 4)
            return "Administrator";

        if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-501") == sidText.length() - 4)
            return "Guest";

        return "";
    }

    static
    string
    getGroupsAttrText(
        __in uint32_t attr,
        __in bool     pureText = false
        )
    {
        static CBitFieldAnalyzer s_GroupsAttrAnalyzer{ {
            { 0x00000004, "enabled" },
            { 0x00000002, "default" },
            { 0x00000020, "integrity" },
            { 0x00000040, "integrity-enabled" },
            { 0xC0000000, "logon-id" },
            { 0x00000001, "mandatory" },
            { 0x00000008, "owner" },
            { 0x00000010, "deny-only" },
            { 0x20000000, "resource" }
            } };

        return s_GroupsAttrAnalyzer.GetText(attr, pureText);
    }

    template<typename T>
    T read(size_t addr);

    template<typename T>
    void write(size_t addr, T data);

    bool check();

    size_t m_header_cookie_addr;
    size_t m_type_index_table_addr;
    size_t m_ob_header_cookie;

    //regex m_args_regex;

    map<uint8_t, wstring> m_type_name_map;  
    static const map<const char*, const char*, cmp_str> s_wellknown_sids;
    static const map < const char*, const char*, cmp_str > s_integrity_level_texts;
    static const map < const char*, const char*, cmp_str > s_trust_label_texts;

    CDKOptions m_dk_options;
};

CTokenExt g_ExtInstance;
ExtExtension* g_ExtInstancePtr = &g_ExtInstance;

template<typename T>
inline T CTokenExt::read(size_t addr)
{
    T ret = 0;
    if (S_OK != m_Data->ReadVirtual(addr, &ret, sizeof(T), NULL))
        ThrowRemote(E_ACCESSDENIED, "Fail to read memory");

    return ret;
}

template<typename T>
inline void CTokenExt::write(size_t addr, T data)
{
    if (S_OK != m_Data->WriteVirtual(addr, &data, sizeof(T), NULL))
        ThrowRemote(E_ACCESSDENIED, "Fail to write memory");
}

const map<const char*, const char*, cmp_str> CTokenExt::s_integrity_level_texts{ {
    { "S-1-16-0",         "Integrity Level Untrusted(0)" },
    { "S-1-16-4096",      "Integrity Level Low(1)" },
    { "S-1-16-8192",      "Integrity Level Medium(2)" },
    { "S-1-16-12288",     "Integrity Level High(3)" },
    { "S-1-16-16384",     "Integrity Level System(4)" }
    } };

const map<const char*, const char*, cmp_str> CTokenExt::s_trust_label_texts{ {
    { "S-1-19-512-4096",          "Trust Label Lite(PPL) PsProtectedSignerWindows(5)" },
    { "S-1-19-1024-4096",         "Trust Label Protected(PP) PsProtectedSignerWindows(5)" },
    { "S-1-19-512-8192",          "Trust Label Lite(PPL) PsProtectedSignerTcb(6)" },
    { "S-1-19-1024-8192",         "Trust Label Protected(PP) PsProtectedSignerTcb(6)" }
    } };

const map<const char*, const char*, cmp_str> CTokenExt::s_wellknown_sids{ {
    { "S-1-1-0",          "Everyone" },
    { "S-1-2-0",          "Local" },
    { "S-1-2-1",          "Console Logon" },
    { "S-1-5-18",         "Local System" },
    { "S-1-5-32-544",     "BUILTIN/Administrators" },
    { "S-1-5-32-545",     "BUILTIN/Users" },
    { "S-1-5-32-546",     "BUILTIN/Guests" },
    { "S-1-5-32-555",     "BUILTIN/\\Remote Desktop Users" },
    { "S-1-5-32-578",     "BUILTIN/\\Hyper-V Administrators" }
    } };
