#pragma once

#include <cinttypes>
#include <Windows.h>

#ifdef _WIN64
typedef int64_t IntPtrAbi;
#else
typedef int32_t IntPtrAbi;
#endif
