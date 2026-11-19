// PRUDP (NEX) UDP packet decoder (src/Cemu/nex/prudp.cpp): the same steps prudpClient::Update runs on
// every datagram it receives from a game server: split the datagram with
// prudpPacket::calculateSizeFromPacketData, decode each packet with prudpIncomingPacket (header,
// SYN/CON/DATA options, payload size, checksum) and RC4-decrypt DATA payloads.
#include "Common/precompiled.h"
#include "Cemu/nex/prudp.h"
#include "util/crypto/md5.h"
#include <csignal>

// Cemu's assert_dbg() (precompiled.h) is raise(SIGTRAP). prudp.cpp hits it on network-reachable states
// (calculateSizeFromPacketData on an unknown packet type, a DATA payload-size mismatch). libFuzzer
// installs no SIGTRAP handler, so the process would just die with no report and no artifact. Lift it
// to abort() so ASan/libFuzzer report it as a crash with a stack (c.md: aborting handler from
// LLVMFuzzerInitialize; the assert itself is not hidden).
static void SigtrapToAbort(int)
{
	abort();
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	signal(SIGTRAP, SigtrapToAbort);
	return 0;
}

static void InitStreamSettings(prudpStreamSettings& s, const char* key)
{
	// identical to prudpClient::prudpClient(dstIp, dstPort, key)
	uint8 checksumBase = 0;
	for (sint32 i = 0; key[i] != '\0'; i++)
		checksumBase += key[i];
	s.checksumBase = checksumBase;
	MD5_CTX md5Ctx;
	MD5_Init(&md5Ctx);
	MD5_Update(&md5Ctx, key, (int)strlen(key));
	MD5_Final(s.accessKeyDigest, &md5Ctx);
	RC4_initCtx(&s.rc4Server, "CD&ML");
	RC4_initCtx(&s.rc4Client, "CD&ML");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	// prudpClient::Update receives into a 4096-byte buffer
	uint8 receiveBuffer[4096];
	if (size > sizeof(receiveBuffer))
		return -1;
	memcpy(receiveBuffer, data, size);
	sint32 r = (sint32)size;

	// stream state is per connection; reset per input (the friends service key, nexFriends.cpp)
	prudpStreamSettings settings{};
	InitStreamSettings(settings, "ridfebb9");

	sint32 pIdx = 0;
	while (pIdx < r)
	{
		sint32 packetLength = prudpPacket::calculateSizeFromPacketData(receiveBuffer + pIdx, r - pIdx);
		if (packetLength <= 0 || (pIdx + packetLength) > r)
			break;
		auto incomingPacket = std::make_unique<prudpIncomingPacket>(&settings, receiveBuffer + pIdx, packetLength);
		pIdx += packetLength;
		if (incomingPacket->hasError())
			break;
		if (incomingPacket->type == prudpPacket::TYPE_DATA && incomingPacket->hasData)
			incomingPacket->decrypt();
		volatile size_t n = incomingPacket->packetData.size();
		(void)n;
	}
	return 0;
}
