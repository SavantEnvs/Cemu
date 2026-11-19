// FileCache container (src/Cemu/FileCache/FileCache.cpp): the shader/pipeline cache format
// (header, file table, zlib-compressed entries). Shader caches are commonly downloaded and shared
// between users; Cemu opens them with FileCache::Open when a title boots.
#include "Common/precompiled.h"
#include "Cemu/FileCache/FileCache.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::string path = fuzz_write_temp_file(data, size, ".bin");
	if (path.empty())
		return 0;
	FileCache* fc = FileCache::Open(fs::path(path));
	if (fc)
	{
		std::vector<uint8> out;
		sint32 count = fc->GetFileCount();
		sint32 maxIdx = fc->GetMaximumFileIndex();
		uint64 n1 = 0, n2 = 0;
		for (sint32 i = 0; i <= maxIdx && i < 64; i++)
		{
			if (fc->GetFileByIndex(i, &n1, &n2, out))
			{
				// look the same entry up again by name, as the shader cache loader does
				(void)fc->HasFile({n1, n2});
				fc->GetFile({n1, n2}, out);
			}
		}
		(void)count;
		fc->GetFile({0, 0}, out);
		delete fc;
	}
	unlink(path.c_str());
	return 0;
}
