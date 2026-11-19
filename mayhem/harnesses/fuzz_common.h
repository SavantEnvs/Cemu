// Shared helpers for the Cemu fuzz harnesses (mayhem/ layer, not upstream code).
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

// Writes the fuzz input to a fresh file in $TMPDIR (default /tmp) and returns its path, or ""
// on failure. The caller unlinks it. Cemu's file-format readers (WUX, WUHB, FileCache) only take
// a filesystem path, exactly as the emulator does when the user opens a game/cache file.
static inline std::string fuzz_write_temp_file(const uint8_t* data, size_t size, const char* suffix)
{
	const char* tmp = getenv("TMPDIR");
	if (!tmp || !*tmp)
		tmp = "/tmp";
	std::string path = std::string(tmp) + "/cemu_fuzz_XXXXXX" + suffix;
	int fd = mkstemps(path.data(), (int)strlen(suffix));
	if (fd < 0)
		return {};
	size_t off = 0;
	while (off < size)
	{
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0)
		{
			close(fd);
			unlink(path.c_str());
			return {};
		}
		off += (size_t)w;
	}
	close(fd);
	return path;
}
