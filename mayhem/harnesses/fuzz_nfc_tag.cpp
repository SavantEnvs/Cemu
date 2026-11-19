// Amiibo / NFC tag dump parser: TagV0 (locked area, capability container, TLV list) and the NDEF
// message/record decoder. Cemu feeds a user-selected tag dump file to TagV0::FromBytes when a tag is
// "scanned" (src/Cafe/OS/libs/nfc/nfc.cpp: nfc::TouchTagFromFile), then ndef::Message::FromBytes on
// the NDEF TLV it extracted.
#include "Common/precompiled.h"
#include "Cafe/OS/libs/nfc/TagV0.h"
#include "Cafe/OS/libs/nfc/TLV.h"
#include "Cafe/OS/libs/nfc/ndef.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::vector<std::byte> buf((const std::byte*)data, (const std::byte*)data + size);
	std::span<const std::byte> in(buf.data(), buf.size());

	// Same sequence as nfc::TouchTagFromFile: tag -> NDEF data -> NDEF message -> records.
	auto tag = TagV0::FromBytes(in);
	if (tag)
	{
		auto ndefMsg = ndef::Message::FromBytes(tag->GetNDEFData());
		if (ndefMsg)
		{
			for (const auto& rec : *ndefMsg)
			{
				volatile size_t n = rec.GetPayload().size() + rec.GetType().size() + rec.GetID().size();
				(void)n;
			}
			(void)ndefMsg->ToBytes();
		}
		// Not called: TagV0::ToBytes() (the write-back path, nfc.cpp after a guest NFCWrite). It
		// copies 8 bytes per unlocked block from the packed data area without checking its size, so it
		// overflows the heap on every tag whose TLVs don't fill the whole tag, i.e. on every valid input,
		// which would stop the fuzzer from exploring the read path at all.
		volatile size_t n = tag->GetNDEFData().size() + tag->GetLockedArea().size();
		(void)n;
	}

	// The NDEF and TLV decoders on their own (nfc.cpp also decodes NDEF data written by the game).
	auto msg = ndef::Message::FromBytes(in);
	if (msg)
		(void)msg->ToBytes();
	std::span<std::byte> mut(buf.data(), buf.size());
	auto tlvs = TLV::FromBytes(mut);
	for (const auto& t : tlvs)
		(void)t.ToBytes();
	return 0;
}
