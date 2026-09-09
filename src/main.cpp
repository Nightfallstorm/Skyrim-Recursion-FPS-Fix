#include "hooks.h"
#include "Version.h"
#include <spdlog/sinks/basic_file_sink.h>

namespace {
	void InitializeLog()
	{
		auto path = logger::log_directory();
		if (!path.has_value()) {
			//stl::report_and_fail("Failed to find standard logging directory"sv); // Doesn't work in VR
		}

		*path /= Project::NAME;
		*path += ".log"sv;
		auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true);

		auto log = std::make_shared<spdlog::logger>("global log"s, std::move(sink));

		log->set_level(spdlog::level::info);
		log->flush_on(spdlog::level::info);

		spdlog::set_default_logger(std::move(log));
		spdlog::set_pattern("[%H:%M:%S:%e] %v"s);

		logger::info(FMT_STRING("{} v{}"), Project::NAME, Project::Version::NAME);
	}

	void InitializeHooking() {
		logger::trace("Initializing StackFrameOverflow hook...");
		StackOverFlowHook::Install();
		StackOverFlowLogHook::Install();
	}
}

SKSEPluginInfo(
	.Version = {Project::Version::MAJOR, Project::Version::MINOR, Project::Version::PATCH},
	.Name = "TBD",
	.Author = "TBD",
	.SupportEmail = "TBD",
	.StructCompatibility = SKSE::StructCompatibility::Independent,
)

extern "C" DLLEXPORT const char* APIENTRY GetPluginVersion()
{
	return Project::Version::NAME.data();
}


SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
	InitializeLog();
	SKSE::Init(a_skse);
	InitializeHooking();
	logger::info("Loaded Plugin");
	return true;
}
