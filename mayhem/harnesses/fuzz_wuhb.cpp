// WUHB (Wii U homebrew bundle, RomFS) reader: header, dir/file hash tables, entry tables, path lookup
// and file reads (src/Cafe/Filesystem/WUHB/WUHBReader.cpp). Mirrors what Cemu does with a .wuhb the
// user opens: TitleInfo looks up meta/meta.ini and code/, and fscDeviceWuhb walks directories via
// GetDirEntry/GetFileEntry linked lists and reads files with ReadFromFile.
#include "Common/precompiled.h"
#include "Cafe/Filesystem/WUHB/WUHBReader.h"
#include "fuzz_common.h"

// Upper bound on entries visited per input. The entry lists are linked lists whose links come from the
// file, so a cyclic list would loop forever in the walker below; the bound keeps the harness itself
// finite (Cemu's directory iterator stops when the guest stops iterating).
static constexpr int kMaxVisits = 256;

static void ReadSomeOfFile(WUHBReader* r, uint32 fileOfs)
{
	uint64 sz = r->GetFileSize(fileOfs);
	uint8 buf[512];
	r->ReadFromFile(fileOfs, 0, sizeof(buf), buf);
	if (sz > 16)
		r->ReadFromFile(fileOfs, sz - 16, sizeof(buf), buf);
}

static void Walk(WUHBReader* r, uint32 dirOfs, int& visits)
{
	if (dirOfs == ROMFS_ENTRY_EMPTY || ++visits > kMaxVisits)
		return;
	romfs_direntry_t dir = r->GetDirEntry(dirOfs);
	uint32 f = dir.fileListHead;
	while (f != ROMFS_ENTRY_EMPTY && ++visits <= kMaxVisits)
	{
		romfs_fentry_t fe = r->GetFileEntry(f);
		ReadSomeOfFile(r, f);
		f = fe.listNext;
	}
	uint32 d = dir.dirListHead;
	while (d != ROMFS_ENTRY_EMPTY && visits <= kMaxVisits)
	{
		romfs_direntry_t de = r->GetDirEntry(d);
		Walk(r, d, visits);
		d = de.listNext;
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::string path = fuzz_write_temp_file(data, size, ".wuhb");
	if (path.empty())
		return 0;
	WUHBReader* r = WUHBReader::FromPath(fs::path(path));
	if (r)
	{
		for (const char* p : {"meta/meta.ini", "code/root.rpx", "meta/iconTex.tga", "content/a/b.bin"})
		{
			uint32 ofs = r->Lookup(p, true);
			if (ofs != ROMFS_ENTRY_EMPTY)
				ReadSomeOfFile(r, ofs);
		}
		for (const char* p : {"", "code", "meta", "content"})
			(void)r->Lookup(p, false);
		int visits = 0;
		Walk(r, 0, visits);
		delete r;
	}
	unlink(path.c_str());
	return 0;
}
