// IniParser: the parser behind graphic pack rules.txt, game profiles and WUHB meta.ini
// (src/util/IniParser/IniParser.cpp). Mirrors GraphicPack2::LoadGraphicPack's use: iterate every
// section, list its options and look up named ones.
#include "Common/precompiled.h"
#include "util/IniParser/IniParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::vector<char> buf((const char*)data, (const char*)data + size);
	IniParser ini(std::span<char>(buf.data(), buf.size()), "fuzz.ini");
	size_t total = 0;
	while (ini.NextSection())
	{
		total += ini.GetCurrentSectionName().size() + ini.GetCurrentSectionLineNumber();
		for (auto& [k, v] : ini.GetAllOptions())
			total += k.size() + v.size();
		for (const char* name : {"name", "version", "rendererFilter", "path", "titleIds"})
		{
			auto opt = ini.FindOption(name);
			if (opt)
				total += opt->size();
		}
	}
	volatile size_t sink = total;
	(void)sink;
	return 0;
}
