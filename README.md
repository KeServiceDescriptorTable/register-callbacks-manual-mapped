# register-callbacks-manual-mapped

```c
#include <memory.hpp>
#include <system.hpp>

void create_process_routine(PEPROCESS process, HANDLE process_id,
	PPS_CREATE_NOTIFY_INFO create_info) {
	DbgPrint("create process routine");
}

OB_PREOP_CALLBACK_STATUS pre_process_handle_callback(void* context, POB_PRE_OPERATION_INFORMATION information) {
	DbgPrint("pre process handle callback");
	return OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
}

void post_process_handle_callback(void* context, POB_POST_OPERATION_INFORMATION information) {
	DbgPrint("post process handle callback");
}

OB_PREOP_CALLBACK_STATUS pre_thread_handle_callback(void* context, POB_PRE_OPERATION_INFORMATION information) {
	DbgPrint("pre thread handle callback");
	return OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
}

void post_thread_handle_callback(void* context, POB_POST_OPERATION_INFORMATION information) {
	DbgPrint("post process handle callback");
}

NTSTATUS FxDriverEntry() {
	auto* ntoskrnl = system::get_system_module(L"ntoskrnl.exe");
	if (!ntoskrnl)
		return STATUS_UNSUCCESSFUL;

	auto mm_verify_callback_function_check_flags = memory::virtual_memory::pattern_scan({ (std::uint64_t)ntoskrnl->DllBase, ntoskrnl->SizeOfImage }, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x00\x8B\xFA\x48\x8B\xF1",
		"xxxx?xxxx?xxxx?xxxx?xxxxx");

	if (!mm_verify_callback_function_check_flags)
		return STATUS_UNSUCCESSFUL;

	const std::uint8_t shellcode[] = { 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3 };
	std::uint8_t original_instructions[sizeof(shellcode)] = {};

	memcpy(original_instructions, (void*)mm_verify_callback_function_check_flags,
		sizeof(original_instructions));

	auto mapped = memory::physical_memory::map(
		memory::physical_memory::get_physical_for_virtual(mm_verify_callback_function_check_flags),
		sizeof(original_instructions)
	);

	if (!mapped)
		return STATUS_UNSUCCESSFUL;

	memcpy((void*)mapped, shellcode,
		sizeof(shellcode));

	PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)create_process_routine, false);

	OB_OPERATION_REGISTRATION ob_operation_registration[2] = {};
	ob_operation_registration[0].ObjectType = PsProcessType;
	ob_operation_registration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ob_operation_registration[0].PostOperation = post_process_handle_callback;
	ob_operation_registration[0].PreOperation = pre_process_handle_callback;

	ob_operation_registration[1].ObjectType = PsThreadType;
	ob_operation_registration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ob_operation_registration[1].PostOperation = post_thread_handle_callback;
	ob_operation_registration[1].PreOperation = pre_thread_handle_callback;

	OB_CALLBACK_REGISTRATION ob_callback_registration = {};
	ob_callback_registration.Version = OB_FLT_REGISTRATION_VERSION;
	ob_callback_registration.OperationRegistrationCount = sizeof(ob_operation_registration) / sizeof(ob_operation_registration[0]);
	ob_callback_registration.Altitude = RTL_CONSTANT_STRING(L"1969.69");
	ob_callback_registration.OperationRegistration = ob_operation_registration;

	void* handle = nullptr;
	ObRegisterCallbacks(&ob_callback_registration, &handle);

	memcpy((void*)mapped, original_instructions,
		sizeof(original_instructions));

	memory::physical_memory::unmap(mapped, sizeof(original_instructions));

	return STATUS_SUCCESS;
}
```
