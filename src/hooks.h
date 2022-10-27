#pragma once
#include "PCH.h"
struct StackOverFlowHook
{
	static RE::BSFixedString* thunk(std::uint64_t unk0, RE::BSScript::Stack* a_stack, std::uint64_t* a_funcCallQuery)
	{
		if (a_stack != nullptr && a_stack->frames > 1000) {
			RE::BSScript::Internal::IFuncCallQuery::CallType ignore;
			RE::BSTSmartPointer<RE::BSScript::ObjectTypeInfo> scriptInfo;
			RE::BSScript::Variable ignore2;
			RE::BSScrapArray<RE::BSScript::Variable> ignore3;
			RE::BSFixedString functionName;
			a_stack->owningTasklet.get()->GetFunctionCallInfo(ignore, scriptInfo, functionName, ignore2, ignore3);
			logger::info("Detected 1000+  call on function {} for script {}", functionName, scriptInfo.get()->GetName());
			if (IsCallInStack(a_stack, scriptInfo.get()->GetName(), functionName.c_str()) == true) {
				auto message = std::format("Warning, function {} in script {} got stuck in a recursion loop. Exited loop to prevent performance issues. Please notify author to fix and check papyrus logs for more info", functionName.c_str(), scriptInfo.get()->GetName());
				RE::DebugMessageBox(message.c_str());
				*a_funcCallQuery = 0;
			} else {
				// might be a regular native call or something not directly causing recursion, don't break it yet
			}
			
		}
		return func(unk0, a_stack, a_funcCallQuery);
	}

	static bool IsCallInStack(RE::BSScript::Stack* a_stack, const char* scriptName, const char* functionName) {
		RE::BSScript::StackFrame* stackFrame = a_stack->top;
		if (stackFrame == nullptr) {
			return false;
		}
		stackFrame = stackFrame->previousFrame; // Get the frame before the current function call, as we don't want to check against ourselves
		while (stackFrame != nullptr) { // Loop through all frames in the stack
			if (stackFrame->owningFunction && stackFrame->owningFunction.get()) {
				if (iequals(std::string(stackFrame->owningFunction.get()->GetObjectTypeName().c_str()), scriptName) &&
					iequals(std::string(stackFrame->owningFunction.get()->GetName().c_str()), functionName)) {
					return true;
				}
			}
			stackFrame = stackFrame->previousFrame;
		}
		return false;
	}

	static bool iequals(const std::string& a, const std::string& b)
	{
		std::size_t sz = a.size();
		if (b.size() != sz)
			return false;
		for (unsigned int i = 0; i < sz; ++i)
			if (tolower(a[i]) != tolower(b[i]))
				return false;
		return true;
	}

	static inline REL::Relocation<decltype(thunk)> func;

	// Install our hook at the specified address
	static inline void Install()
	{
		REL::Relocation<std::uintptr_t> target{ RELOCATION_ID(98130, 104853), REL::VariantOffset(0x7F, 0x7F, 0x7F) };
		stl::write_thunk_call<StackOverFlowHook>(target.address());

		logger::info("StackFrameOverFlow hooked at address {}", fmt::format("{:x}", target.address()));
		logger::info("StackFrameOverFlow hooked at offset {}", fmt::format("{:x}", target.offset()));
	}
};

struct StackOverFlowLogHook
{
	static void thunk(RE::BSScript::Stack* a_stack, const char* a_source, std::uint32_t unk2, char* unk3, std::uint32_t sizeInBytes)
	{
		if (a_stack != nullptr && a_stack->frames > 1000) {
			func(a_stack, "StackFrameOverFlow exception, function call exceeded 1000 call stack limit - returning None", unk2, unk3, sizeInBytes);
		} else {
			func(a_stack, a_source, unk2, unk3, sizeInBytes);
		}
	}

	static inline REL::Relocation<decltype(thunk)> func;

	// Install our hook at the specified address
	static inline void Install()
	{
		REL::Relocation<std::uintptr_t> target{ RELOCATION_ID(98130, 104853), REL::VariantOffset(0x963, 0x97A, 0x963) };
		stl::write_thunk_call<StackOverFlowLogHook>(target.address());

		logger::info("StackFrameOverFlowLog hooked at address {}", fmt::format("{:x}", target.address()));
		logger::info("StackFrameOverFlowLog hooked at offset {}", fmt::format("{:x}", target.offset()));
	}
};
