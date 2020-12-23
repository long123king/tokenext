#pragma once

#pragma warning( disable : 4005)
#pragma warning( disable : 4101)
#pragma warning( disable : 4129)
#pragma warning( disable : 4267)


#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <tuple>
#include <iomanip>
#include <fstream>
#include <regex>
#include <set>
using namespace std;
               
#define INITGUID
#define EXT_CLASS CTokenExt 
#include "../inc/engextcpp10.hpp"
#include "HandleTable.h"

#define REG_RAX     0
#define REG_RCX     1
#define REG_RDX     2
#define REG_RBX     3
#define REG_RSP     4
#define REG_RBP     5
#define REG_RSI     6
#define REG_RDI     7
#define REG_R8      8
#define REG_R9      9
#define REG_R10     10
#define REG_R11     11
#define REG_R12     12
#define REG_R13     13
#define REG_R14     14
#define REG_R15     15
#define REG_RIP     16

class CPoolHeader
{
public:
	CPoolHeader(size_t data)
	{
		memcpy(this, &data, 8);
	}

	uint32_t prev_size : 8;
	uint32_t pool_index : 8;
	uint32_t block_size : 8;
	uint32_t pool_type : 8;
	char tag[4];
};

//kd> dt _POOL_TRACKER_BIG_PAGES
//nt!_POOL_TRACKER_BIG_PAGES
//+ 0x000 Va               : Uint8B
//+ 0x008 Key : Uint4B
//+ 0x00c Pattern : Pos 0, 8 Bits
//+ 0x00c PoolType : Pos 8, 12 Bits
//+ 0x00c SlushSize : Pos 20, 12 Bits
//+ 0x010 NumberOfBytes : Uint8B

class CBigPoolHeader
{
public:
	CBigPoolHeader(uint8_t* data)
	{
		memcpy(this, data, 0x18);
	}

	size_t va;
	char tag[4];
	uint32_t pattern : 8;
	uint32_t pool_type : 12;
	uint32_t slush_size : 12;
	size_t size;
};

/****************************************************
*                               8          5   2 1 0
*                               |          |   | | |
*                               V          V   V V V
* ___________________________________________________
* |                            | |        | | | | | |
* |____________________________|_|________|_|_|_|_|_|
*                               ^          ^   ^ ^ ^
*                               |          |   | | |
*                               |          |   | | 0: Non-Paged Pool
*                               |          |   | | 1: Paged Pool
*                               |          |   | |
*                               |          |   | 1: Must Succeed (0x02)
*                               |          |   |
*                               |          |   |
*                               |          |   1: Cache Aligned (0x04)
*                               |          |
*                               |          |
*                               |          1: Session Pool (0x20)
*                               |
*                               |
*                               1: NX, No Execute (0x200)
*
*****************************************************/

#define NonPagedPool                            0x0000
#define NonPagedPoolExecute                     0x0000
#define NonPagedPoolBase                        0x0000

#define PagedPool                               0x0001

#define NonPagedPoolMustSucceed                 0x0002
#define NonPagedPoolBaseMustSucceed             0x0002

#define DontUseThisType                         0x0003

#define NonPagedPoolCacheAligned                0x0004
#define NonPagedPoolBaseCacheAligned            0x0004

#define PagedPoolCacheAligned                   0x0005

#define NonPagedPoolCacheAlignedMustS           0x0006
#define NonPagedPoolBaseCacheAlignedMustS       0x0006

#define MaxPoolType                             0x0007

#define NonPagedPoolSession                     0x0020
#define PagedPoolSession                        0x0021
#define NonPagedPoolMustSucceedSession          0x0022
#define DontUseThisTypeSession                  0x0023
#define NonPagedPoolCacheAlignedSession         0x0024
#define PagedPoolCacheAlignedSession            0x0025
#define NonPagedPoolCacheAlignedMustSSession    0x0026

#define NonPagedPoolNx                          0x0200
#define NonPagedPoolNxCacheAligned              0x0204

#define NonPagedPoolSessionNx                   0x0220

struct PTE64
{
    size_t Valid : 1;
    size_t Write : 1;
    size_t Owner : 1;
    size_t WriteThrough : 1;
    size_t CacheDisabled : 1;
    size_t Accessed : 1;
    size_t Dirty : 1;
    size_t LargePage : 1;
    size_t Global : 1;
    size_t SoftCopyOnWrite : 1;
    size_t SoftPrototype : 1;
    size_t SoftWrite : 1;
    size_t PageFrameNumber : 28;
    size_t Reserved : 12;
    size_t SoftWorkingSetIndex : 11;
    size_t NoExecute : 1;

	PTE64(size_t source)
	{
		memcpy(this, &source, 8);
	}

    size_t PFN()
    {
        return (size_t)PageFrameNumber << 12;       
    }          

    bool valid() { return Valid != 0; }
    bool write() { return Write != 0; }
    bool owner() { return Owner != 0; }
    bool writeThrough() { return WriteThrough != 0; }
    bool cache() { return CacheDisabled == 0; }
    bool accessed() { return Accessed != 0; }
    bool dirty() { return Dirty != 0; }
    bool large() { return LargePage != 0; }
    bool global() { return Global != 0; }
    bool softCow() { return SoftCopyOnWrite != 0; }
    bool softProto() { return SoftPrototype != 0; }
    bool softWrite() { return SoftWrite != 0; }
    bool nx() { return NoExecute != 0; }
    size_t workingsetIndex() { return SoftWorkingSetIndex; }

    string str()
    {
        stringstream ss;
        ss << (valid() ? "Valid" : "invalid") << " "
            << (write() ? "Write" : "readonly") << " "
            << (owner() ? "Usermode" : "kernelmode") << " "
            << (accessed() ? "Accessed" : "noaccess") << " "
            << (dirty() ? "Dirty" : "no-dirty") << " "
            << (large() ? "Large" : "no-large") << " "
            << (global() ? "Global" : "no-global") << " "
            << (softCow() ? "CopyOnWrite" : "no-copyonwrite") << " "
            << (softWrite() ? "SoftWrite" : "no-softwrite") << " "
            << (nx() ? "NX" : "no-NX") << " ";
            ;

        return ss.str();
    }
};

struct PS_FLAGS
{
	uint32_t CreateReported : 1;
	uint32_t NoDebugInherit : 1;
	uint32_t ProcessExiting : 1;
	uint32_t ProcessDelete : 1;
	uint32_t ControlFlowGuardEnabled : 1;
	uint32_t VmDeleted : 1;
	uint32_t OutswapEnabled : 1;
	uint32_t Outswapped : 1;
	uint32_t FailFastOnCommitFail : 1;
	uint32_t Wow64VaSpace4Gb : 1;
	uint32_t AddressSpaceInitialized : 2;
	uint32_t SetTimerResolution : 1;
	uint32_t BreakOnTermination : 1;
	uint32_t DeprioritizeViews : 1;
	uint32_t WriteWatch : 1;
	uint32_t ProcessInSession : 1;
	uint32_t OverrideAddressSpace : 1;
	uint32_t HasAddressSpace : 1;
	uint32_t LaunchPrefetched : 1;
	uint32_t Background : 1;
	uint32_t VmTopDown : 1;
	uint32_t ImageNotifyDone : 1;
	uint32_t PdeUpdateNeeded : 1;
	uint32_t VdmAllowed : 1;
	uint32_t ProcessRundown : 1;
	uint32_t ProcessInserted : 1;
	uint32_t DefaultIoPriority : 3;
	uint32_t ProcessSelfDelete : 1;
	uint32_t SetTimerResolutionLink : 1;


	PS_FLAGS(uint32_t source)
	{
		memcpy(this, &source, 4);
	}

	string str()
	{
		stringstream ss;
		
		if (CreateReported != 0) ss << setw(50) << " CreateReported \n";
		if (NoDebugInherit != 0) ss << setw(50) << " NoDebugInherit \n";
		if (ProcessExiting != 0) ss << setw(50) << " ProcessExiting \n";
		if (ProcessDelete != 0) ss << setw(50) << " ProcessDelete \n";
		if (ControlFlowGuardEnabled != 0) ss << setw(50) << " ControlFlowGuardEnabled " << "\t\t[Mitigation]\n";
		if (VmDeleted != 0) ss << setw(50) << " VmDeleted \n";
		if (OutswapEnabled != 0) ss << setw(50) << " OutswapEnabled \n";
		if (Outswapped != 0) ss << setw(50) << " Outswapped \n";
		if (FailFastOnCommitFail != 0) ss << setw(50) << " FailFastOnCommitFail \n";
		if (Wow64VaSpace4Gb != 0) ss << setw(50) << " Wow64VaSpace4Gb \n";

		if (SetTimerResolution != 0) ss << setw(50) << " SetTimerResolution \n";
		if (BreakOnTermination != 0) ss << setw(50) << " BreakOnTermination \n";
		if (DeprioritizeViews != 0) ss << setw(50) << " DeprioritizeViews \n";
		if (WriteWatch != 0) ss << setw(50) << " WriteWatch \n";
		if (ProcessInSession != 0) ss << setw(50) << " ProcessInSession \n";
		if (OverrideAddressSpace != 0) ss << setw(50) << " OverrideAddressSpace \n";
		if (HasAddressSpace != 0) ss << setw(50) << " HasAddressSpace \n";
		if (LaunchPrefetched != 0) ss << setw(50) << " LaunchPrefetched \n";
		if (Background != 0) ss << setw(50) << " Background \n";
		if (VmTopDown != 0) ss << setw(50) << " VmTopDown \n";
		if (ImageNotifyDone != 0) ss << setw(50) << " ImageNotifyDone \n";
		if (PdeUpdateNeeded != 0) ss << setw(50) << " PdeUpdateNeeded \n";
		if (VdmAllowed != 0) ss << setw(50) << " VdmAllowed \n";
		if (ProcessRundown != 0) ss << setw(50) << " ProcessRundown \n";
		if (ProcessInserted != 0) ss << setw(50) << " ProcessInserted \n";

		if (ProcessSelfDelete != 0) ss << setw(50) << " ProcessSelfDelete \n";
		if (SetTimerResolutionLink != 0) ss << setw(50) << " SetTimerResolutionLink \n";

		ss << setw(50) << "AddressSpaceInitialized : " << hex << setw(8) << AddressSpaceInitialized << "\n"
			<< setw(50) << "DefaultIoPriority : " << hex << setw(8) << DefaultIoPriority;

		return ss.str();
	}
};

struct PS_FLAGS3
{
	uint32_t Minimal : 1;
	uint32_t ReplacingPageRoot : 1;
	uint32_t DisableNonSystemFonts : 1;
	uint32_t AuditNonSystemFontLoading : 1;
	uint32_t Crashed : 1;
	uint32_t JobVadsAreTracked : 1;
	uint32_t VadTrackingDisabled : 1;
	uint32_t AuxiliaryProcess : 1;
	uint32_t SubsystemProcess : 1;
	uint32_t IndirectCpuSets : 1;
	uint32_t InPrivate : 1;
	uint32_t ProhibitRemoteImageMap : 1;
	uint32_t ProhibitLowILImageMap : 1;
	uint32_t SignatureMitigationOptIn : 1;
	uint32_t DisableDynamicCodeAllowOptOut : 1;
	uint32_t EnableFilteredWin32kAPIs : 1;
	uint32_t AuditFilteredWin32kAPIs : 1;
	uint32_t PreferSystem32Images : 1;
	uint32_t RelinquishedCommit : 1;
	uint32_t AutomaticallyOverrideChildProcessPolicy : 1;
	uint32_t HighGraphicsPriority : 1;
	uint32_t CommitFailLogged : 1;
	uint32_t ReserveFailLogged : 1;

	PS_FLAGS3(uint32_t source)
	{
		memcpy(this, &source, 4);
	}

	string str()
	{
		stringstream ss;

		if ( Minimal != 0) ss << setw(50) << " Minimal \n";
		if ( ReplacingPageRoot != 0) ss << setw(50) << " ReplacingPageRoot \n";
		if ( DisableNonSystemFonts != 0) ss << setw(50) << " DisableNonSystemFonts " << "\t\t[Mitigation]\n";
		if ( AuditNonSystemFontLoading != 0) ss << setw(50) << " AuditNonSystemFontLoading \n";
		if ( Crashed != 0) ss << setw(50) << " Crashed \n";
		if ( JobVadsAreTracked != 0) ss << setw(50) << " JobVadsAreTracked \n";
		if ( VadTrackingDisabled != 0) ss << setw(50) << " VadTrackingDisabled \n";
		if ( AuxiliaryProcess != 0) ss << setw(50) << " AuxiliaryProcess \n";
		if ( SubsystemProcess != 0) ss << setw(50) << " SubsystemProcess \n";
		if ( IndirectCpuSets != 0) ss << setw(50) << " IndirectCpuSets \n";
		if ( InPrivate != 0) ss << setw(50) << " InPrivate \n";
		if ( ProhibitRemoteImageMap != 0) ss << setw(50) << " ProhibitRemoteImageMap " << "\t\t[Mitigation]\n";
		if ( ProhibitLowILImageMap != 0) ss << setw(50) << " ProhibitLowILImageMap " << "\t\t[Mitigation]\n";
		if ( SignatureMitigationOptIn != 0) ss << setw(50) << " SignatureMitigationOptIn \n";
		if ( DisableDynamicCodeAllowOptOut != 0) ss << setw(50) << " DisableDynamicCodeAllowOptOut \n";
		if ( EnableFilteredWin32kAPIs != 0) ss << setw(50) << " EnableFilteredWin32kAPIs " << "\t\t[Mitigation]\n";
		if ( AuditFilteredWin32kAPIs != 0) ss << setw(50) << " AuditFilteredWin32kAPIs \n";
		if ( PreferSystem32Images != 0) ss << setw(50) << " PreferSystem32Images " << "\t\t[Mitigation]\n";
		if ( RelinquishedCommit != 0) ss << setw(50) << " RelinquishedCommit \n";
		if ( AutomaticallyOverrideChildProcessPolicy != 0) ss << setw(50) << " AutomaticallyOverrideChildProcessPolicy \n";
		if ( HighGraphicsPriority != 0) ss << setw(50) << " HighGraphicsPriority \n";
		if ( CommitFailLogged != 0) ss << setw(50) << " CommitFailLogged \n";
		if ( ReserveFailLogged != 0) ss << setw(50) << " ReserveFailLogged \n";

		return ss.str();
	}
};

struct PS_FLAGS2
{
	uint32_t JobNotReallyActive : 1;
	uint32_t AccountingFolded : 1;
	uint32_t NewProcessReported : 1;
	uint32_t ExitProcessReported : 1;
	uint32_t ReportCommitChanges : 1;
	uint32_t LastReportMemory : 1;
	uint32_t ForceWakeCharge : 1;
	uint32_t CrossSessionCreate : 1;
	uint32_t NeedsHandleRundown : 1;
	uint32_t RefTraceEnabled : 1;
	uint32_t DisableDynamicCode : 1;
	uint32_t EmptyJobEvaluated : 1;
	uint32_t DefaultPagePriority : 3;
	uint32_t PrimaryTokenFrozen : 1;
	uint32_t ProcessVerifierTarget : 1;
	uint32_t StackRandomizationDisabled : 1;
	uint32_t AffinityPermanent : 1;
	uint32_t AffinityUpdateEnable : 1;
	uint32_t PropagateNode : 1;
	uint32_t ExplicitAffinity : 1;
	uint32_t ProcessExecutionState : 2;
	uint32_t DisallowStrippedImages : 1;
	uint32_t HighEntropyASLREnabled : 1;
	uint32_t ExtensionPointDisable : 1;
	uint32_t ForceRelocateImages : 1;
	uint32_t ProcessStateChangeRequest : 2;
	uint32_t ProcessStateChangeInProgress : 1;
	uint32_t DisallowWin32kSystemCalls : 1;

	PS_FLAGS2(uint32_t source)
	{
		memcpy(this, &source, 4);
	}

	string str()
	{
		stringstream ss;

		if ( JobNotReallyActive != 0) ss << setw(50) << " JobNotReallyActive \n";
		if ( AccountingFolded != 0) ss << setw(50) << " AccountingFolded \n";
		if ( NewProcessReported != 0) ss << setw(50) << " NewProcessReported \n";
		if ( ExitProcessReported != 0) ss << setw(50) << " ExitProcessReported \n";
		if ( ReportCommitChanges != 0) ss << setw(50) << " ReportCommitChanges \n";
		if ( LastReportMemory != 0) ss << setw(50) << " LastReportMemory \n";
		if ( ForceWakeCharge != 0) ss << setw(50) << " ForceWakeCharge \n";
		if ( CrossSessionCreate != 0) ss << setw(50) << " CrossSessionCreate \n";
		if ( NeedsHandleRundown != 0) ss << setw(50) << " NeedsHandleRundown \n";
		if ( RefTraceEnabled != 0) ss << setw(50) << " RefTraceEnabled \n";
		if ( DisableDynamicCode != 0) ss << setw(50) << " DisableDynamicCode \n";
		if ( EmptyJobEvaluated != 0) ss << setw(50) << " EmptyJobEvaluated \n";

		if ( PrimaryTokenFrozen != 0) ss << setw(50) << " PrimaryTokenFrozen \n";
		if ( ProcessVerifierTarget != 0) ss << setw(50) << " ProcessVerifierTarget \n";
		if ( StackRandomizationDisabled != 0) ss << setw(50) << " StackRandomizationDisabled \n";
		if ( AffinityPermanent != 0) ss << setw(50) << " AffinityPermanent \n";
		if ( AffinityUpdateEnable != 0) ss << setw(50) << " AffinityUpdateEnable \n";
		if ( PropagateNode != 0) ss << setw(50) << " PropagateNode \n";
		if ( ExplicitAffinity != 0) ss << setw(50) << " ExplicitAffinity \n";

		if ( DisallowStrippedImages != 0) ss << setw(50) << " DisallowStrippedImages " << "\t\t[Mitigation]\n";
		if ( HighEntropyASLREnabled != 0) ss << setw(50) << " HighEntropyASLREnabled " << "\t\t[Mitigation]\n";
		if ( ExtensionPointDisable != 0) ss << setw(50) << " ExtensionPointDisable " << "\t\t[Mitigation]\n";
		if ( ForceRelocateImages != 0) ss << setw(50) << " ForceRelocateImages " << "\t\t[Mitigation]\n";

		if ( ProcessStateChangeInProgress != 0) ss << setw(50) << " ProcessStateChangeInProgress \n";
		if ( DisallowWin32kSystemCalls != 0) ss << setw(50) << " DisallowWin32kSystemCalls " << "\t\t[Mitigation]\n";

		ss << setw(50) << " DefaultPagePriority : " << hex << setw(8) << DefaultPagePriority << "\n"
			<< setw(50) << "ProcessExecutionState : " << hex << setw(8) << ProcessExecutionState << "\n"
			<< setw(50) << "ProcessStateChangeRequest : " << hex << setw(8) << ProcessStateChangeRequest;

		return ss.str();
	}
};

#pragma pack(pop)

#pragma pack(push, 1)
struct SEP_TOKEN_PRIVILEGES
{
    size_t     Present;
    size_t     Enabled;
    size_t     EnabledByDefault;
};

struct SEP_AUDIT_POLICY
{
    uint8_t     AdtTokenPolicy[0x1e];
    uint8_t     PolicySetStatus[0x01];
    uint8_t     Reserved[0x01];
};

struct SEP_LOGON_SESSION_REFERENCES
{
    SEP_LOGON_SESSION_REFERENCES*       Next;
    LUID                                LogonId;
    LUID                                BuddyLogonId;
    size_t                              ReferenceCount;
    uint32_t                            Flags;
    PVOID                               pDeviceMap;
    PVOID                               Token;
    UNICODE_STRING                      AccountName;
    UNICODE_STRING                      AuthorityName;
    uint8_t                             LowBoxHandlesTable[0x10]; // 0
    uint8_t                             SharedDataLock[0x08]; // 0
    PVOID                               SharedClaimAttributes;
    PVOID                               SharedSidValues;
    PVOID                               RevocationBlock_Infos_Flink;
    PVOID                               RevocationBlock_Infos_Blink;
    uint8_t                             RevocationBlock_Lock[0x08];
    uint8_t                             RevocationBlock_Rundown[0x08];
    PVOID                               ServerSilo;
    LUID                                SiblingAuthId;
};


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

class POOL_METRICS
{
public:
    size_t _pool_addr;
    size_t _pool_index;
    size_t _pool_type;
    size_t _pool_start;
    size_t _pool_end;
    size_t _total_pages;
    size_t _total_bytes;
    size_t _total_big_pages;
    string _comment;
    vector<size_t> _pending_frees;
    map<size_t, vector<size_t>> _free_lists;
};

bool is_alpha(uint8_t ch)
{
	if (ch >= '0' && ch <= '9')
		return true;

	if (ch >= 'A' && ch <= 'Z')
		return true;

	if (ch >= 'a' && ch <= 'z')
		return true;

	return false;
}

class CBuffer
{
public:
    CBuffer(size_t len)
        :m_len(len)
    {
        m_buffer = new (nothrow) uint8_t[len];
        if (m_buffer == nullptr)
            m_len = 0;
        else
            memset(m_buffer, 0, m_len);
    }
    ~CBuffer()
    {
        if (valid())
        {
            delete[] m_buffer;
            m_buffer = nullptr;
            m_len = 0;
        }
    }

    uint8_t* ptr()
    {
        return m_buffer;
    }

    size_t len()
    {
        return m_len;
    }

    bool valid()
    {
        return m_buffer != nullptr;
    }

    template<class T>
    bool set(size_t offset, T content)
    {
        if (offset >= m_len)
            return false;

        *(reinterpret_cast<T*>(m_buffer + offset)) = content;
        return true;
    }

private:
    uint8_t* m_buffer;
    size_t  m_len;
};

class CTokenExt 
    : public ExtExtension
    //, public IDebugEventCallbacks
    //, public IDebugOutputCallbacks
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


public:

    size_t readDbgDataAddr(ULONG index);

    wstring getTypeName(size_t index);

	template<class T>
	bool is_in_range(T value, T min, T max);

    void initialize();

    void dump_user_modules();

    void dump_kernel_modules();

    uint8_t realIndex(size_t type_index, size_t obj_hdr_addr);

    void dump_obj(size_t obj_addr, bool b_simple = false);

	string wstr2str(wstring wstr);

    void dump_process(size_t process_addr);

    void dump_handle_table(size_t handle_table_addr);

    void dump_kernel_handle_table();

    void dump_process_handle_table(size_t process_addr);

    void dump_sdr(size_t sd_addr, string type_name = "File");

    void dump_pool_handles(size_t table_addr, size_t count);

    void dump_token(size_t token_addr);

    void dump_session(size_t session_addr);

    void kill_process(size_t proc_addr);

    void dump_logon_sessions();

    void token_privilege_add(size_t token_addr, size_t bitmap);

    void dump_process_threads(size_t process_addr);

	void dump_pool(size_t addr);

	void dump_args();

    size_t find_proc(string name);

    void dump_free_pool(size_t size);

    void dump_threads_stack(size_t process_addr);

    void dump_all_threads_stack();

    void dig_link(size_t addr);

    void tpool(size_t addr);

    void poolhdr(size_t addr);


	void dump_page_info(size_t addr);

	void dump_pages_around(size_t addr);

    void dump_pool_metrics();

    void dump_pe_guid(size_t addr);

    void dump_session_pool();

    void dump_session_space(size_t addr);

    void dump_page_dir(size_t proc_addr, bool user_mode_only = true);

    string dump_obj_ref(size_t addr);

    vector<size_t> dump_avl_entries(size_t addr);

    bool VisitSide(size_t addr, vector<size_t>& entries);

    string ctime(time_t* time);

    string fctime(time_t* time);

    HRESULT x(string cmd);

	string x_output(string cmd);

    size_t reg(size_t reg);

    size_t reg_of(const char* reg);

    tuple<size_t, size_t> get_thread_token(size_t thread_addr);

    string dump_luid(size_t addr);

    tuple<string, string> dump_sid(size_t sid_addr);

    string dump_guid(size_t addr);

    string dump_sid_attr_array(size_t sid_addr, size_t count);

    size_t get_sid_attr_array_item(size_t sid_addr, size_t count, size_t index);

    string dump_sid_attr_hash(size_t addr);

    size_t get_sid_attr_hash_item(size_t addr, size_t index);

    string dump_acl(size_t acl_addr, string type_name = "File");

    string dump_privilege(size_t addr);

    string dump_privileges_by_bitmap(size_t bitmap);

    string privilege_bit_to_text(size_t bit_offset);

    void do_memcpy(size_t src_addr, size_t dst_addr, size_t count);

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

	void dump_ps_flags(size_t addr);

    void dump_big_pool();

    void dump_pool_track();

    void dump_pool_range();

    void traverse_linked_list(size_t head);

    void dump_trap_frame(size_t thread_addr);

    void dump_types();

    void dump_hole(size_t addr);

    size_t curr_proc();

    size_t curr_thread();

    size_t curr_tid();

    size_t curr_token();

    void dump_usage();

	size_t get_cr3();

    void dump_modules();

	void dump_size(size_t value);

	void dump_va_regions();

	void dump_regs();

    void pte(size_t addr);

	void analyze_qword(size_t value);

	void analyze_mem(size_t start, size_t len);

	bool like_kaddr(size_t addr);

	bool in_user_heap(size_t addr);

	bool in_curr_stack(size_t addr);

	bool in_paged_pool(size_t addr);

	bool in_non_paged_pool(size_t addr);

	bool in_small_pool_page(size_t addr);

	tuple<bool, size_t, string, string> as_kcode(size_t addr);
	tuple<bool, size_t, string, string> as_ucode(size_t addr);

	// bool: is_Small_or_large_pool
	// bool: is_Paged_or_nonpaged_pool
	// bool: is_Allocated_or_free_pool
	// size_t: pool_start_addr
	// size_t: pool_size (exclude header size)
	// string: tag
	tuple<bool, bool, bool, size_t, size_t, string> as_small_pool(size_t addr);

	tuple<bool, bool, bool, size_t, size_t, string> as_large_pool(size_t addr);

    void dump_token_buffer(size_t addr);

    bool is_reg(string& str);

    size_t getIntArg(vector<string>& args, size_t idx, size_t default_val);

    static
    string
    getIntegrityLevel(
        __in const string& sidText
        )
    {
        auto it = s_integrity_level_texts.find(sidText.c_str());

        if (it != s_integrity_level_texts.end())
            return it->second;

        return sidText;
    }

    static
    string
    getImpersonationLevel(
        __in const size_t level
    )
    {
        static map<size_t, const char*> s_impersonation_level_map{ {
            { SecurityAnonymous, "SecurityAnonymous" },
            { SecurityIdentification, "SecurityIdentification" },
            { SecurityImpersonation, "SecurityImpersonation" },
            { SecurityDelegation, "SecurityDelegation" },
        } };

        auto it = s_impersonation_level_map.find(level);

        if (it != s_impersonation_level_map.end())
            return it->second;

        return "";
    }

	static
	string
	getAceTypeStr(
		__in const size_t ace_type
	)
	{
		static map<size_t, const char*> s_ace_type_map{
			{ ACCESS_ALLOWED_ACE_TYPE				 , "[Allow]" },
			{ ACCESS_DENIED_ACE_TYPE			     , "[Deny ]" },
			{ SYSTEM_AUDIT_ACE_TYPE					 , "[Audit]" },
			{ SYSTEM_ALARM_ACE_TYPE					 , "[Alarm]" },
			{ ACCESS_ALLOWED_COMPOUND_ACE_TYPE        , "[Allow_Compound]" },
			{ ACCESS_ALLOWED_OBJECT_ACE_TYPE          , "[Allow_Object]" },
			{ ACCESS_DENIED_OBJECT_ACE_TYPE           , "[Deny_Object]" },
			{ SYSTEM_AUDIT_OBJECT_ACE_TYPE            , "[Audit_Object]" },
			{ SYSTEM_ALARM_OBJECT_ACE_TYPE            , "[Alarm_Object]" },
			{ ACCESS_ALLOWED_CALLBACK_ACE_TYPE        , "[Allow_Callback]" },
			{ ACCESS_DENIED_CALLBACK_ACE_TYPE         , "[Deny_Callback]" },
			{ ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE , "[Allow_Callback_Object]" },
			{ ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  , "[Deny_Callback_Object]" },
			{ SYSTEM_AUDIT_CALLBACK_ACE_TYPE          , "[Audit_Callback]" },
			{ SYSTEM_ALARM_CALLBACK_ACE_TYPE          , "[Alarm_Callback]" },
			{ SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   , "[Audit_Callback_Object]" },
			{ SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   , "[Alarm_Callback_Object]" },
			{ SYSTEM_MANDATORY_LABEL_ACE_TYPE         , "[Madatory_Label]" },
			{ SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      , "[Resource_Attribute]" },
			{ SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        , "[Scoped_Policy_Id]" },
			{ SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE     , "[Process_Trust_Label]" },
		};

		auto it = s_ace_type_map.find(ace_type);
		if (it != s_ace_type_map.end())
			return it->second;

		return "[     ]";
	}

	static
		string
		getAceMaskStr(
		__in const size_t ace_mask,
		__in string type_name = "File",
		__in bool     pureText = false
	)
	{
		static CBitFieldAnalyzer s_AceMaskAnalyzer{ {
			{DELETE                  , "DELETE"},                           //(0x00010000L)
			{READ_CONTROL            , "READ_CONTROL"},                     //(0x00020000L)
			{WRITE_DAC               , "WRITE_DAC" },                       //(0x00040000L)
			{WRITE_OWNER             , "WRITE_OWNER" },                     //(0x00080000L)
			{SYNCHRONIZE             , "SYNCHRONIZE" },                     //(0x00100000L)
			{ACCESS_SYSTEM_SECURITY  , "ACCESS_SYSTEM_SECURITY" },          //(0x01000000L)
			{MAXIMUM_ALLOWED         , "MAXIMUM_ALLOWED" },                 //(0x02000000L)
			{GENERIC_READ            , "GENERIC_READ" },                    //(0x80000000L)
			{GENERIC_WRITE           , "GENERIC_WRITE" },                   //(0x40000000L)
			{GENERIC_EXECUTE         , "GENERIC_EXECUTE" },                 //(0x20000000L)
			{GENERIC_ALL             , "GENERIC_ALL" },                     //(0x10000000L)
			} };

		string generic_mask_str = s_AceMaskAnalyzer.GetText(ace_mask & 0xFFFF0000, pureText);

		auto specific_mask = ace_mask & 0xffff;

		generic_mask_str += " ";
		generic_mask_str += type_name;
		generic_mask_str += ": ";
		
		if (type_name == "Token")
			generic_mask_str += getTokenSpecificAccess(specific_mask, pureText);
		else if (type_name == "Process")
			generic_mask_str += getProcessSpecificAccess(specific_mask, pureText);
		else if (type_name == "Thread")
			generic_mask_str += getThreadSpecificAccess(specific_mask, pureText);
		else if (type_name == "Directory")
			generic_mask_str += getDirectorySpecificAccess(specific_mask, pureText);
		else if (type_name == "Section")
			generic_mask_str += getSectionSpecificAccess(specific_mask, pureText);
		else if (type_name == "Mutant")
			generic_mask_str += getMutantSpecificAccess(specific_mask, pureText);
		else if (type_name == "Semaphore")
			generic_mask_str += getSemaphoreSpecificAccess(specific_mask, pureText);
		else if (type_name == "Event")
			generic_mask_str += getEventSpecificAccess(specific_mask, pureText);
		else if (type_name == "TmTx")
			generic_mask_str += getTxSpecificAccess(specific_mask, pureText);
		else if (type_name == "TmTm")
			generic_mask_str += getTxMSpecificAccess(specific_mask, pureText);
		else if (type_name == "TmRm")
			generic_mask_str += getRMSpecificAccess(specific_mask, pureText);
		else if (type_name == "Timer")
			generic_mask_str += getTimerSpecificAccess(specific_mask, pureText);
		else if (type_name == "Job")
			generic_mask_str += getJobSpecificAccess(specific_mask, pureText);
		else if (type_name == "Key")
			generic_mask_str += getKeySpecificAccess(specific_mask, pureText);
		else if (type_name == "TmEn")
			generic_mask_str += getEnlistSpecificAccess(specific_mask, pureText);
		else if (type_name == "IoCompletion")
			generic_mask_str += getIoCSpecificAccess(specific_mask, pureText);
		else// if (type_name == "File")
			generic_mask_str += getFileSpecificAccess(specific_mask, pureText);

		return generic_mask_str;
	}

	static 
	string
	getTokenSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {
			{ TOKEN_ASSIGN_PRIMARY, "TOKEN_ASSIGN_PRIMARY"},  // #define TOKEN_ASSIGN_PRIMARY    (0x0001)
			{ TOKEN_DUPLICATE, "TOKEN_DUPLICATE" },  // #define TOKEN_DUPLICATE         (0x0002)
			{ TOKEN_IMPERSONATE, "TOKEN_IMPERSONATE" },  // #define TOKEN_IMPERSONATE       (0x0004)
			{ TOKEN_QUERY, "TOKEN_QUERY" },  // #define TOKEN_QUERY             (0x0008)
			{ TOKEN_QUERY_SOURCE, "TOKEN_QUERY_SOURCE" },  // #define TOKEN_QUERY_SOURCE      (0x0010)
			{ TOKEN_ADJUST_PRIVILEGES, "TOKEN_ADJUST_PRIVILEGES" },  // #define TOKEN_ADJUST_PRIVILEGES (0x0020)
			{ TOKEN_ADJUST_GROUPS, "TOKEN_ADJUST_GROUPS" },  // #define TOKEN_ADJUST_GROUPS     (0x0040)
			{ TOKEN_ADJUST_DEFAULT, "TOKEN_ADJUST_DEFAULT" },  // #define TOKEN_ADJUST_DEFAULT    (0x0080)
			{ TOKEN_ADJUST_SESSIONID, "TOKEN_ADJUST_SESSIONID" },  // #define TOKEN_ADJUST_SESSIONID  (0x0100)
	    } };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}
			
	static
	string
	getProcessSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {//
			{ PROCESS_TERMINATE, "PROCESS_TERMINATE" },  // #define PROCESS_TERMINATE                  (0x0001)
			{ PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD" },  // #define PROCESS_CREATE_THREAD              (0x0002)
			{ PROCESS_SET_SESSIONID, "PROCESS_SET_SESSIONID" },  // #define PROCESS_SET_SESSIONID              (0x0004)
			{ PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION" },  // #define PROCESS_VM_OPERATION               (0x0008)
			{ PROCESS_VM_READ, "PROCESS_VM_READ" },  // #define PROCESS_VM_READ                    (0x0010)
			{ PROCESS_VM_WRITE, "PROCESS_VM_WRITE" },  // #define PROCESS_VM_WRITE                   (0x0020)
			{ PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE" },  // #define PROCESS_DUP_HANDLE                 (0x0040)
			{ PROCESS_CREATE_PROCESS, "PROCESS_CREATE_PROCESS" },  // #define PROCESS_CREATE_PROCESS             (0x0080)
			{ PROCESS_SET_QUOTA, "PROCESS_SET_QUOTA" },  // #define PROCESS_SET_QUOTA                  (0x0100)
			{ PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION" },  // #define PROCESS_SET_INFORMATION            (0x0200)
			{ PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION" },  // #define PROCESS_QUERY_INFORMATION          (0x0400)
			{ PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME" },  // #define PROCESS_SUSPEND_RESUME             (0x0800)
			{ PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION" },  // #define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
			{ PROCESS_SET_LIMITED_INFORMATION, "PROCESS_SET_LIMITED_INFORMATION" },  // #define PROCESS_SET_LIMITED_INFORMATION    (0x2000)
			} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}
	static
	string
	getThreadSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		 static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {//
		 	{ THREAD_TERMINATE, "THREAD_TERMINATE" },  // #define THREAD_TERMINATE                 (0x0001)
		 	{ THREAD_SUSPEND_RESUME, "THREAD_SUSPEND_RESUME" },  // #define THREAD_SUSPEND_RESUME            (0x0002)
		 	{ THREAD_GET_CONTEXT, "THREAD_GET_CONTEXT" },  // #define THREAD_GET_CONTEXT               (0x0008)
		 	{ THREAD_SET_CONTEXT, "THREAD_SET_CONTEXT" },  // #define THREAD_SET_CONTEXT               (0x0010)
		 	{ THREAD_QUERY_INFORMATION, "THREAD_QUERY_INFORMATION" },  // #define THREAD_QUERY_INFORMATION         (0x0040)
		 	{ THREAD_SET_INFORMATION, "THREAD_SET_INFORMATION" },  // #define THREAD_SET_INFORMATION           (0x0020)
		 	{ THREAD_SET_THREAD_TOKEN, "THREAD_SET_THREAD_TOKEN" },  // #define THREAD_SET_THREAD_TOKEN          (0x0080)
		 	{ THREAD_IMPERSONATE, "THREAD_IMPERSONATE" },  // #define THREAD_IMPERSONATE               (0x0100)
		 	{ THREAD_DIRECT_IMPERSONATION, "THREAD_DIRECT_IMPERSONATION" },  // #define THREAD_DIRECT_IMPERSONATION      (0x0200)
		 	{ THREAD_SET_LIMITED_INFORMATION, "THREAD_SET_LIMITED_INFORMATION" },  // #define THREAD_SET_LIMITED_INFORMATION   (0x0400)
		 	{ THREAD_QUERY_LIMITED_INFORMATION, "THREAD_QUERY_LIMITED_INFORMATION" },  // #define THREAD_QUERY_LIMITED_INFORMATION (0x0800)
		 	{ THREAD_RESUME, "THREAD_RESUME" },  // #define THREAD_RESUME                    (0x1000)
		 	} };
		 
		 return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getJobSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ { //
			{ JOB_OBJECT_ASSIGN_PROCESS, "JOB_OBJECT_ASSIGN_PROCESS" },  // #define JOB_OBJECT_ASSIGN_PROCESS           (0x0001)
			{ JOB_OBJECT_SET_ATTRIBUTES, "JOB_OBJECT_SET_ATTRIBUTES" },  // #define JOB_OBJECT_SET_ATTRIBUTES           (0x0002)
			{ JOB_OBJECT_QUERY, "JOB_OBJECT_QUERY" },  // #define JOB_OBJECT_QUERY                    (0x0004)
			{ JOB_OBJECT_TERMINATE, "JOB_OBJECT_TERMINATE" },  // #define JOB_OBJECT_TERMINATE                (0x0008)
			{ JOB_OBJECT_SET_SECURITY_ATTRIBUTES, "JOB_OBJECT_SET_SECURITY_ATTRIBUTES" },  // #define JOB_OBJECT_SET_SECURITY_ATTRIBUTES  (0x0010)
			} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getEventSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {				   //
			{ EVENT_MODIFY_STATE, "EVENT_MODIFY_STATE" },  // #define EVENT_MODIFY_STATE      0x0002
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getMutantSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ { //
			{ MUTANT_QUERY_STATE, "MUTANT_QUERY_STATE" },  // #define MUTANT_QUERY_STATE      0x0001
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getSemaphoreSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ { //
			{ SEMAPHORE_MODIFY_STATE, "SEMAPHORE_MODIFY_STATE" },  // #define SEMAPHORE_MODIFY_STATE      0x0002
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getTimerSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {		   //
			{ TIMER_QUERY_STATE, "TIMER_QUERY_STATE" },  // #define TIMER_QUERY_STATE       0x0001
			{ TIMER_MODIFY_STATE, "TIMER_MODIFY_STATE" },  // #define TIMER_MODIFY_STATE      0x0002
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getSectionSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {   //
			{ SECTION_QUERY, "SECTION_QUERY" },  // #define SECTION_QUERY                0x0001
			{ SECTION_MAP_WRITE, "SECTION_MAP_WRITE" },  // #define SECTION_MAP_WRITE            0x0002
			{ SECTION_MAP_READ, "SECTION_MAP_READ" },  // #define SECTION_MAP_READ             0x0004
			{ SECTION_MAP_EXECUTE, "SECTION_MAP_EXECUTE" },  // #define SECTION_MAP_EXECUTE          0x0008
			{ SECTION_EXTEND_SIZE, "SECTION_EXTEND_SIZE" },  // #define SECTION_EXTEND_SIZE          0x0010
			{ SECTION_MAP_EXECUTE_EXPLICIT, "SECTION_MAP_EXECUTE_EXPLICIT" },  // #define SECTION_MAP_EXECUTE_EXPLICIT 0x0020
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getFileSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {					   //
		// // File
			{ FILE_READ_DATA, "FILE_READ_DATA" },  // #define FILE_READ_DATA            ( 0x0001 )    // file & pipe
			{ FILE_WRITE_DATA, "FILE_WRITE_DATA" },  // #define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
			{ FILE_APPEND_DATA, "FILE_APPEND_DATA" },  // #define FILE_APPEND_DATA          ( 0x0004 )    // file
			{ FILE_READ_EA, "FILE_READ_EA" },  // #define FILE_READ_EA              ( 0x0008 )    // file & directory
			{ FILE_WRITE_EA, "FILE_WRITE_EA" },  // #define FILE_WRITE_EA             ( 0x0010 )    // file & directory
			{ FILE_EXECUTE, "FILE_EXECUTE" },  // #define FILE_EXECUTE              ( 0x0020 )    // file
			{ FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES" },  // #define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all
			{ FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES" },  // #define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getDirectorySpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {		 //
		// // Directory
			{ FILE_LIST_DIRECTORY, "FILE_LIST_DIRECTORY" },  // #define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory
			{ FILE_ADD_FILE, "FILE_ADD_FILE" },  // #define FILE_ADD_FILE             ( 0x0002 )    // directory
			{ FILE_ADD_SUBDIRECTORY, "FILE_ADD_SUBDIRECTORY" },  // #define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
			{ FILE_READ_EA, "FILE_READ_EA" },  // #define FILE_READ_EA              ( 0x0008 )    // file & directory
			{ FILE_WRITE_EA, "FILE_WRITE_EA" },  // #define FILE_WRITE_EA             ( 0x0010 )    // file & directory
			{ FILE_TRAVERSE, "FILE_TRAVERSE" },  // #define FILE_TRAVERSE             ( 0x0020 )    // directory
			{ FILE_DELETE_CHILD, "FILE_DELETE_CHILD" },  // #define FILE_DELETE_CHILD         ( 0x0040 )    // directory
			{ FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES" },  // #define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all
			{ FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES" },  // #define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getPipeSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {		 //
		// // Pipe
			{ FILE_READ_DATA, "FILE_READ_DATA" },  // #define FILE_READ_DATA            ( 0x0001 )    // file & pipe
			{ FILE_WRITE_DATA, "FILE_WRITE_DATA" },  // #define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
			{ FILE_CREATE_PIPE_INSTANCE, "FILE_CREATE_PIPE_INSTANCE" },  // #define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe
			{ FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES" },  // #define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all
			{ FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES" },  // #define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getIoCSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {		 //
			{ IO_COMPLETION_MODIFY_STATE, "IO_COMPLETION_MODIFY_STATE" },  // #define IO_COMPLETION_MODIFY_STATE  0x0002
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getKeySpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {					   //
			{ KEY_QUERY_VALUE, "KEY_QUERY_VALUE" },  // #define KEY_QUERY_VALUE         (0x0001)
			{ KEY_SET_VALUE, "KEY_SET_VALUE" },  // #define KEY_SET_VALUE           (0x0002)
			{ KEY_CREATE_SUB_KEY, "KEY_CREATE_SUB_KEY" },  // #define KEY_CREATE_SUB_KEY      (0x0004)
			{ KEY_ENUMERATE_SUB_KEYS, "KEY_ENUMERATE_SUB_KEYS" },  // #define KEY_ENUMERATE_SUB_KEYS  (0x0008)
			{ KEY_NOTIFY, "KEY_NOTIFY" },  // #define KEY_NOTIFY              (0x0010)
			{ KEY_CREATE_LINK, "KEY_CREATE_LINK" },  // #define KEY_CREATE_LINK         (0x0020)
			{ KEY_WOW64_32KEY, "KEY_WOW64_32KEY" },  // #define KEY_WOW64_32KEY         (0x0200)
			{ KEY_WOW64_64KEY, "KEY_WOW64_64KEY" },  // #define KEY_WOW64_64KEY         (0x0100)
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getTxMSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ { //
			{ TRANSACTIONMANAGER_QUERY_INFORMATION, "TRANSACTIONMANAGER_QUERY_INFORMATION" },  // #define TRANSACTIONMANAGER_QUERY_INFORMATION     ( 0x0001 )
			{ TRANSACTIONMANAGER_SET_INFORMATION, "TRANSACTIONMANAGER_SET_INFORMATION" },  // #define TRANSACTIONMANAGER_SET_INFORMATION       ( 0x0002 )
			{ TRANSACTIONMANAGER_RECOVER, "TRANSACTIONMANAGER_RECOVER" },  // #define TRANSACTIONMANAGER_RECOVER               ( 0x0004 )
			{ TRANSACTIONMANAGER_RENAME, "TRANSACTIONMANAGER_RENAME" },  // #define TRANSACTIONMANAGER_RENAME                ( 0x0008 )
			{ TRANSACTIONMANAGER_CREATE_RM, "TRANSACTIONMANAGER_CREATE_RM" },  // #define TRANSACTIONMANAGER_CREATE_RM             ( 0x0010 )
			{ TRANSACTIONMANAGER_BIND_TRANSACTION, "TRANSACTIONMANAGER_BIND_TRANSACTION" },  // #define TRANSACTIONMANAGER_BIND_TRANSACTION      ( 0x0020 )
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getTxSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {										 //
			{ TRANSACTION_QUERY_INFORMATION, "TRANSACTION_QUERY_INFORMATION" },  // #define TRANSACTION_QUERY_INFORMATION     ( 0x0001 )
			{ TRANSACTION_SET_INFORMATION, "TRANSACTION_SET_INFORMATION" },  // #define TRANSACTION_SET_INFORMATION       ( 0x0002 )
			{ TRANSACTION_ENLIST, "TRANSACTION_ENLIST" },  // #define TRANSACTION_ENLIST                ( 0x0004 )
			{ TRANSACTION_COMMIT, "TRANSACTION_COMMIT" },  // #define TRANSACTION_COMMIT                ( 0x0008 )
			{ TRANSACTION_ROLLBACK, "TRANSACTION_ROLLBACK" },  // #define TRANSACTION_ROLLBACK              ( 0x0010 )
			{ TRANSACTION_PROPAGATE, "TRANSACTION_PROPAGATE" },  // #define TRANSACTION_PROPAGATE             ( 0x0020 )
			{ TRANSACTION_RIGHT_RESERVED1, "TRANSACTION_RIGHT_RESERVED1" },  // #define TRANSACTION_RIGHT_RESERVED1       ( 0x0040 )
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getRMSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {							 //
			{ RESOURCEMANAGER_QUERY_INFORMATION, "RESOURCEMANAGER_QUERY_INFORMATION" },  // #define RESOURCEMANAGER_QUERY_INFORMATION     ( 0x0001 )
			{ RESOURCEMANAGER_SET_INFORMATION, "RESOURCEMANAGER_SET_INFORMATION" },  // #define RESOURCEMANAGER_SET_INFORMATION       ( 0x0002 )
			{ RESOURCEMANAGER_RECOVER, "RESOURCEMANAGER_RECOVER" },  // #define RESOURCEMANAGER_RECOVER               ( 0x0004 )
			{ RESOURCEMANAGER_ENLIST, "RESOURCEMANAGER_ENLIST" },  // #define RESOURCEMANAGER_ENLIST                ( 0x0008 )
			{ RESOURCEMANAGER_GET_NOTIFICATION, "RESOURCEMANAGER_GET_NOTIFICATION" },  // #define RESOURCEMANAGER_GET_NOTIFICATION      ( 0x0010 )
			{ RESOURCEMANAGER_REGISTER_PROTOCOL, "RESOURCEMANAGER_REGISTER_PROTOCOL" },  // #define RESOURCEMANAGER_REGISTER_PROTOCOL     ( 0x0020 )
			{ RESOURCEMANAGER_COMPLETE_PROPAGATION, "RESOURCEMANAGER_COMPLETE_PROPAGATION" },  // #define RESOURCEMANAGER_COMPLETE_PROPAGATION  ( 0x0040 )
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
	}

	static
	string
	getEnlistSpecificAccess(
		__in size_t access,
		__in bool     pureText = false)
	{
		static CBitFieldAnalyzer s_SpecificAccessAnalyzer{ {											   //
			{ ENLISTMENT_QUERY_INFORMATION, "ENLISTMENT_QUERY_INFORMATION" },  // #define ENLISTMENT_QUERY_INFORMATION     ( 0x0001 )
			{ ENLISTMENT_SET_INFORMATION, "ENLISTMENT_SET_INFORMATION" },  // #define ENLISTMENT_SET_INFORMATION       ( 0x0002 )
			{ ENLISTMENT_RECOVER, "ENLISTMENT_RECOVER" },  // #define ENLISTMENT_RECOVER               ( 0x0004 )
			{ ENLISTMENT_SUBORDINATE_RIGHTS, "ENLISTMENT_SUBORDINATE_RIGHTS" },  // #define ENLISTMENT_SUBORDINATE_RIGHTS    ( 0x0008 )
			{ ENLISTMENT_SUPERIOR_RIGHTS, "ENLISTMENT_SUPERIOR_RIGHTS" },  // #define ENLISTMENT_SUPERIOR_RIGHTS       ( 0x0010 )
		} };

		return s_SpecificAccessAnalyzer.GetText(access, pureText);
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

		auto it1 = s_integrity_level_texts.find(sidText.c_str());

		if (it1 != s_integrity_level_texts.end())
			return it1->second;

		auto it2 = s_trust_label_texts.find(sidText.c_str());

		if (it2 != s_trust_label_texts.end())
			return it2->second;

        if (sidText.find("S-1-5-5-") == 0 && sidText.rfind("-") > 7)
            return "Logon Session";

        if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-500") == sidText.length() - 4)
            return "Administrator";

        if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-501") == sidText.length() - 4)
            return "Guest";

		if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-512") == sidText.length() - 4)
			return "Domain Admins";

		if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-512") == sidText.length() - 4)
			return "Domain Admins";

		if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-513") == sidText.length() - 4)
			return "Domain Users";

		if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-514") == sidText.length() - 4)
			return "Domain Guests";

		if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-515") == sidText.length() - 4)
			return "Domain Computers";

		if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-516") == sidText.length() - 4)
			return "Domain Controllers";

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

	static
		string
		getPteFlagText(
			__in size_t pte,
			__in bool     pureText = false
		)
	{
		static CBitFieldAnalyzer s_PageFlagsText{ {
			{ 0x00000001, "valid" },
			{ 0x00000002, "write" },
			{ 0x00000004, "owner" },
			{ 0x00000008, "write-through" },
			{ 0x00000010, "cache-disabled" },
			{ 0x00000020, "accessed" },
			{ 0x00000040, "dirty" },
			{ 0x00000080, "large-page" },
			{ 0x00000100, "global" },
			{ 0x00000200, "s-copy-on-write" },
			{ 0x00000400, "s-prototype" },
			{ 0x00000800, "s-write" },
			} };

		string flag_str = s_PageFlagsText.GetText(pte, pureText);

		if (pte & 0x8000000000000000)
			flag_str += "|NX";

		return flag_str;
	}

    template<typename T>
    T read(size_t addr);

    template<typename T>
    T readX(size_t addr);

    template<typename T>
    void write(size_t addr, T data);

    bool check();

    size_t m_header_cookie_addr;
    size_t m_type_index_table_addr;
    size_t m_ob_header_cookie;

    size_t m_debug_cbk_ref{ 1 };

    regex m_pool_entry_re;

    //regex m_args_regex;

    map<uint8_t, wstring> m_type_name_map;  
    static const map<const char*, const char*, cmp_str> s_wellknown_sids;
    static const map < const char*, const char*, cmp_str > s_integrity_level_texts;
    static const map < const char*, const char*, cmp_str > s_trust_label_texts;

    ULONG m_ref_count;
    string m_pattern;
    PDEBUG_CLIENT m_new_client{nullptr};
	PDEBUG_CLIENT m_output_side_client{ nullptr };
    size_t m_bp_offset{ 0 };

    bool m_trace_next{ false };
    bool m_trace_err{ false };

    bool m_b_silent{ false };

    map<size_t, set<size_t>> m_trace_packs;
    map<size_t, size_t> m_trace_funcs;

    map<size_t, string> m_icall_map;

    size_t m_curr_frame_num{ 0 };

    string m_last_cmd_output;

    vector<tuple<uint64_t, uint64_t, uint64_t, uint64_t>> m_mem_accesses;

    //vector<shared_ptr<kdlib::AutoBreakpoint<CTokenExt>>> m_breakpoints;
};

CTokenExt g_ExtInstance;
ExtExtension* g_ExtInstancePtr = &g_ExtInstance;

template<class T>
inline bool CTokenExt::is_in_range(T value, T min, T max)
{
	return value >= min && value < max;
}

template<typename T>
inline T CTokenExt::read(size_t addr)
{
    T ret = 0;
    if (S_OK != m_Data->ReadVirtual(addr, &ret, sizeof(T), NULL))
        ThrowRemote(E_ACCESSDENIED, "Fail to read memory");

    return ret;
}

template<typename T>
inline T CTokenExt::readX(size_t addr)
{
    T ret = 0;
    if (S_OK != m_Data->ReadPhysical(addr, &ret, sizeof(T), NULL))
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
    { "S-1-16-0",         "Untrusted(0)" },
    { "S-1-16-4096",      "Low(1)" },
    { "S-1-16-8192",      "Medium(2)" },
    { "S-1-16-12288",     "High(3)" },
    { "S-1-16-16384",     "System(4)" },
	{ "S-1-16-20480",     "Protected(5)" },
    } };

const map<const char*, const char*, cmp_str> CTokenExt::s_trust_label_texts{ {
    { "S-1-19-512-4096",          "Trust Label Lite(PPL) PsProtectedSignerWindows(5)" },
    { "S-1-19-1024-4096",         "Trust Label Protected(PP) PsProtectedSignerWindows(5)" },
    { "S-1-19-512-8192",          "Trust Label Lite(PPL) PsProtectedSignerTcb(6)" },
    { "S-1-19-1024-8192",         "Trust Label Protected(PP) PsProtectedSignerTcb(6)" }
    } };

const map<const char*, const char*, cmp_str> CTokenExt::s_wellknown_sids{ {
	{ "S-1-0",				"Null"},
	{ "S-1-1-0",			"Everyone" },
    { "S-1-2-0",			"Local" },
    { "S-1-2-1",			"Console Logon" },
	{ "S-1-3",				"Creator Authority"},
	{ "S-1-3-0",			"Creator Owner"},
	{ "S-1-3-1",			"Creator Group"},
	{ "S-1-3-4",			"Owner Rights"},
	{ "S-1-5-2",			"Network"},
	{ "S-1-5-4",			"Interactive"},
	{ "S-1-5-6",			"Service"},
	{ "S-1-5-7",			"Anonymous"},
	{ "S-1-5-9",			"Enterprise Domain Controllers"},
	{ "S-1-5-10",			"Principal Self"},
	{ "S-1-5-11",			"Authenticated Users"},
	{ "S-1-5-12",			"Restricted Code"},
	{ "S-1-5-13",			"Terminal Server Users"},
	{ "S-1-5-14",			"Remote Interactive Logon"},
	{ "S-1-5-15",			"This Organization"},
	{ "S-1-5-17",			"IUSR"},			
    { "S-1-5-18",           "Local System" },
	{ "S-1-5-19",			"NT Authority/Local Service"},
	{ "S-1-5-20",			"NT Authority/Network Service"},
	{ "S-1-5-32-544",		"BUILTIN/Administrators" },
    { "S-1-5-32-545",		"BUILTIN/Users" },
    { "S-1-5-32-546",		"BUILTIN/Guests" },
    { "S-1-5-32-555",		"BUILTIN/Remote Desktop Users" },
	{ "S-1-5-32-559",		"BUILTIN/Performance Log Users"},
	{ "S-1-5-32-558",		"BUILTIN/Performance Monitor Users"},
	{ "S-1-5-32-578",		"BUILTIN/Hyper-V Administrators" },
	{ "S-1-5-80-0",			"All Services"},
	{ "S-1-5-113",			"Local Account"},
	{ "S-1-5-114",			"Local Account&Member of Admins Group"},
	{ "S-1-5-64-10",		"NTLM Authentication"},
} };
