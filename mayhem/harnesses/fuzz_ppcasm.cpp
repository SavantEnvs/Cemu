// PowerPC assembler + disassembler (src/Cemu/PPCAssembler/ppcAssembler.cpp). Graphic pack
// patches.txt files carry PPC assembly that Cemu assembles line by line with
// ppcAssembler_assembleSingleInstruction (GraphicPack2PatchesParser.cpp); the debugger disassembles
// the resulting words with ppcAssembler_disassemble.
#include "Common/precompiled.h"
#include "Cemu/PPCAssembler/ppcAssembler.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::string text((const char*)data, size);
	uint32 va = 0x02000000;
	size_t pos = 0;
	int lines = 0;
	while (pos <= text.size() && lines++ < 64)
	{
		size_t nl = text.find('\n', pos);
		if (nl == std::string::npos)
			nl = text.size();
		std::string line = text.substr(pos, nl - pos);
		pos = nl + 1;
		PPCAssemblerInOut ctx{};
		ctx.virtualAddress = va;
		if (ppcAssembler_assembleSingleInstruction(line.c_str(), &ctx))
		{
			for (size_t i = 0; i + 4 <= ctx.outputData.size(); i += 4)
			{
				uint32 op = ((uint32)ctx.outputData[i] << 24) | ((uint32)ctx.outputData[i + 1] << 16) |
				            ((uint32)ctx.outputData[i + 2] << 8) | (uint32)ctx.outputData[i + 3];
				PPCDisassembledInstruction dis{};
				ppcAssembler_disassemble(va + (uint32)i, op, &dis);
				(void)ppcAssembler_getInstructionName(dis.ppcAsmCode);
			}
			va += (uint32)ctx.outputData.size();
		}
	}
	// the raw input as big-endian instruction words, as the disassembler sees guest memory
	for (size_t i = 0; i + 4 <= size && i < 256; i += 4)
	{
		uint32 op = ((uint32)data[i] << 24) | ((uint32)data[i + 1] << 16) | ((uint32)data[i + 2] << 8) | data[i + 3];
		PPCDisassembledInstruction dis{};
		ppcAssembler_disassemble(0x02000000 + (uint32)i, op, &dis);
		(void)ppcAssembler_getInstructionName(dis.ppcAsmCode);
	}
	return 0;
}
