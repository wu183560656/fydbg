#pragma once
namespace patch
{
	BOOLEAN RtlDispatchExceptionPatch(PEPROCESS Process);
	BOOLEAN RtlDispatchExceptionRestore(PEPROCESS Process);

	BOOLEAN RtlWow64DispatchExceptionPatch(PEPROCESS Process);
	BOOLEAN RtlWow64DispatchExceptionRestore(PEPROCESS Process);
};

