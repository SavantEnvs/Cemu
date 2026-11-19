// Logging back end for the fuzz harnesses. Cemu's real back end (src/Cemu/Logging/CemuLogging.cpp)
// opens log.txt under the user's settings directory via ActiveSettings/LaunchSettings and runs a
// writer thread, which would pull the whole config + GUI layer into every harness. The fuzzed code
// only calls these entry points; formatting (fmt::format of the message, done in the header
// template) still runs for every enabled message. Only the final write is dropped.
#include "Common/precompiled.h"

uint64 s_loggingFlagMask = cemuLog_getFlag(LogType::Force);

void cemuLog_writeLineToLog(std::string_view text, bool date, bool new_line) { (void)text; }
bool cemuLog_log(LogType type, std::string_view text)
{
	if (!cemuLog_isLoggingEnabled(type))
		return false;
	cemuLog_writeLineToLog(text);
	return true;
}
bool cemuLog_log(LogType type, std::u8string_view text)
{
	return cemuLog_log(type, std::string_view((const char*)text.data(), text.size()));
}
void cemuLog_waitForFlush() {}
void cemuLog_setActiveLoggingFlags(uint64 flagMask) { s_loggingFlagMask = flagMask | cemuLog_getFlag(LogType::Force); }
void cemuLog_logHexDump(LogType type, const void* data, size_t size, size_t lineSize) {}
bool cemuLog_advancedPPCLoggingEnabled() { return false; }

// ncrypto.cpp links iosu_crypto.cpp (console OTP/SEEPROM/certificate state), which locates the
// emulated MLC through ActiveSettings. ActiveSettings.cpp pulls in the renderer, game profiles and
// accounts, so the harnesses report "no MLC configured" (an empty path), as a fresh install does.
// No harness reaches a code path that reads from it.
#include "config/ActiveSettings.h"
fs::path ActiveSettings::GetMlcPath() { return {}; }

// nexFriends.cpp (fuzz_nex) links NexFriends::updateMyPresence, which tags our presence with the
// running title from CafeSystem (the whole emulator core). The harnesses run no title: report none,
// as CafeSystem does before a game is launched. No harness calls updateMyPresence.
#include "Cafe/CafeSystem.h"
TitleId CafeSystem::GetForegroundTitleId() { return 0; }
uint16 CafeSystem::GetForegroundTitleVersion() { return 0; }
