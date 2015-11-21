#pragma once

#include <assert.h>

#ifdef WIN32
#include <intrin.h>
#include <wtypes.h>
#include <sal.h>
#include <winternl.h>
#include <SDKDDKVer.h>
#else
#include <unistd.h>
#endif

#include <memory>

#include <vector>
#include <ctime>
#include <stdlib.h>
#include <cstdlib>

#define POWER2(exp) ((size_t)1 << (exp))

#define MEMBER(cast, ptr, member) reinterpret_cast<cast*>(reinterpret_cast<ULONG_PTR>(ptr) + static_cast<size_t>(member))

using mem_t = std::unique_ptr<void, decltype(&free)>;

#ifdef WINDOWS
#define getpid() GetCurrentProcessId()
#define gettid() GetCurrentThreadId()
#else
#define __in
#define __out
#define __inout
#define __in_opt
#define __in_bcount(x)
#define __out_bcount(x)
#define __inout_bcount(x)
#define __in_ecount(x)

#define __checkReturn
#define __forceinline

template <typename Type, size_t Size>
char(*__countof_helper(Type(&ar)[Size]))[Size];
#define _countof(ar) sizeof(*__countof_helper(ar))

#define _declspec(x) __attribute__((x))

#endif
