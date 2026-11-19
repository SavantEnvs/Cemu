// title.tmd and title.tik parsers (src/Cemu/ncrypto/ncrypto.cpp: NCrypto::TMDParser::parse and
// NCrypto::ETicketParser::parse), which Cemu runs on the TMD/ticket of every installed or opened
// title (FST volumes, NUS downloads). The first input byte selects the parser.
#include "Common/precompiled.h"
#include "Cemu/ncrypto/ncrypto.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	if (size < 1)
		return -1;
	uint8 sel = data[0];
	std::vector<uint8> buf(data + 1, data + size);
	if (sel & 1)
	{
		NCrypto::TMDParser tmd;
		if (tmd.parse(buf.data(), buf.size()))
		{
			uint64 total = tmd.getTitleId() + tmd.getTitleVersion();
			for (auto& c : tmd.GetContentList())
				total += c.contentId + c.index + c.size + c.hash32[0];
			volatile uint64 sink = total;
			(void)sink;
		}
	}
	else
	{
		NCrypto::ETicketParser tik;
		if (tik.parse(buf.data(), buf.size()))
		{
			uint64 total = tik.GetTicketId() + tik.GetTitleId() + tik.GetTicketVersion();
			total += tik.IsPersonalized();
			for (size_t i = 0; i < 64; i++)
				total += tik.CheckRight(i);
			volatile uint64 sink = total;
			(void)sink;
		}
	}
	return 0;
}
