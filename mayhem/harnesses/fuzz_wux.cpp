// WUD/WUX disc image reader (src/Cafe/Filesystem/WUD/wud.cpp): WUX header, sector index table
// and the offset translation behind every read the FST layer makes from a disc image.
#include "Common/precompiled.h"
#include "Cafe/Filesystem/WUD/wud.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::string path = fuzz_write_temp_file(data, size, ".wux");
	if (path.empty())
		return 0;
	wud_t* wud = wud_open(fs::path(path));
	if (wud)
	{
		long long total = wud_getWUDSize(wud);
		(void)wud_isWUXCompressed(wud);
		uint8 buffer[0x2000];
		// Reads at offsets the FST layer would hit: the partition table at 0x18000, the start,
		// the middle, a sector-straddling read and the end of the disc.
		long long offsets[] = {0, 0x18000, total / 2, total / 2 + 0x7FFF, total - 0x100, total};
		for (long long ofs : offsets)
		{
			if (ofs < 0)
				continue;
			wud_readData(wud, buffer, sizeof(buffer), ofs);
		}
		// A few offsets chosen by the input's own trailing bytes.
		if (size >= 8)
		{
			uint64 o;
			memcpy(&o, data + size - 8, 8);
			if (total > 0)
				wud_readData(wud, buffer, sizeof(buffer), (long long)(o % (uint64)total));
		}
		wud_close(wud);
	}
	unlink(path.c_str());
	return 0;
}
