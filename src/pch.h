#pragma once

#include <collection.h>
#include <ppltasks.h>

#ifdef _WIN64
typedef int64 IntPtrAbi;
#else
typedef int32 IntPtrAbi;
#endif
