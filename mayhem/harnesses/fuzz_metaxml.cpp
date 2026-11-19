// meta.xml title metadata parser (src/Cafe/TitleList/ParsedMetaXml.h: ParsedMetaXml::Parse), run by
// TitleInfo and SaveInfo on every title and save Cemu scans. Exceptions are NOT caught here because
// Cemu's callers don't catch them either.
#include "Common/precompiled.h"
#include "Cafe/TitleList/TitleId.h"
#include "Cafe/TitleList/ParsedMetaXml.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::vector<uint8> buf(data, data + size); // Parse loads the buffer in place
	ParsedMetaXml* m = ParsedMetaXml::Parse(buf.data(), buf.size());
	if (m)
	{
		size_t total = 0;
		for (int l = 0; l < 12; l++)
			total += m->GetShortName((CafeConsoleLanguage)l).size() + m->GetLongName((CafeConsoleLanguage)l).size();
		total += m->GetTitleId() + m->GetTitleVersion() + (size_t)m->GetRegion() + m->GetOlvAccesskey();
		total += m->GetProductCode().size() + m->GetCompanyCode().size();
		volatile size_t sink = total;
		(void)sink;
		delete m;
	}
	return 0;
}
