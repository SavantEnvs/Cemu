// Known-answer functional tests over the Cemu parsers the fuzz harnesses target. Cemu ships no test
// suite of its own beyond ExpressionParser_test() (run here, with CEMU_DEBUG_ASSERT so its
// assertions are live) and a base64 self test (NCrypto::unitTests). Each check prints
// "PASS <name>" or "FAIL <name>"; mayhem/test.sh counts them.
#include "Common/precompiled.h"
#include "Cafe/OS/libs/nfc/TagV0.h"
#include "Cafe/OS/libs/nfc/ndef.h"
#include "util/IniParser/IniParser.h"
#include "Cafe/Filesystem/WUD/wud.h"
#include "Cemu/nex/prudp.h"
#include "util/crypto/md5.h"
#include "Cemu/FileCache/FileCache.h"
#include "Cemu/ncrypto/ncrypto.h"
#include "Cemu/ExpressionParser/ExpressionParser.h"
#include "Cemu/PPCAssembler/ppcAssembler.h"
#include "Cafe/TitleList/TitleId.h"
#include "Cafe/TitleList/ParsedMetaXml.h"
#include "fuzz_common.h"

void ExpressionParser_test();

static int g_fail = 0;
static void check(const char* name, bool ok)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", name);
	if (!ok)
		g_fail++;
}

static std::span<const std::byte> bytes(const std::string& s) { return {(const std::byte*)s.data(), s.size()}; }

static void test_expression()
{
	ExpressionParser_test(); // upstream's own asserts; raise(SIGTRAP) on failure
	TExpressionParser<double> ep;
	ep.AddConstant("width", 1280.0);
	check("expression_arith", ep.Evaluate("(width / 2) * 3 + 0x10") == 1936.0);
	bool threw = false;
	try { (void)ep.Evaluate("(1+2"); } catch (const std::exception&) { threw = true; }
	check("expression_mismatch_throws", threw);
	check("expression_upstream_selftest", true);
}

static void test_ini()
{
	std::string s = "# comment\n[Definition]\nname = Foo Bar\nversion=7\n\n[Preset]\n$width = 1920\n";
	std::vector<char> buf(s.begin(), s.end());
	IniParser ini(std::span<char>(buf.data(), buf.size()), "t");
	bool ok = ini.NextSection() && ini.GetCurrentSectionName() == "Definition";
	ok = ok && ini.FindOption("name") == std::optional<std::string_view>("Foo Bar") && ini.FindOption("version") == std::optional<std::string_view>("7");
	ok = ok && ini.NextSection() && ini.GetCurrentSectionName() == "Preset" && ini.GetAllOptions().size() == 1 &&
		 ini.GetAllOptions()[0].first == "$width" && ini.GetAllOptions()[0].second == "1920";
	ok = ok && !ini.NextSection();
	check("ini_sections_options", ok);
}

static void test_ndef()
{
	ndef::Record rec;
	rec.SetTNF(ndef::Record::NDEF_TNF_WKT);
	std::string type = "T", payload = "\x02" "enhello";
	rec.SetType(bytes(type));
	rec.SetPayload(bytes(payload));
	ndef::Message msg;
	msg.append(rec);
	auto data = msg.ToBytes();
	auto parsed = ndef::Message::FromBytes(data);
	bool ok = parsed.has_value();
	if (ok)
	{
		int n = 0;
		for (auto& r : *parsed)
		{
			n++;
			ok = ok && r.GetTNF() == ndef::Record::NDEF_TNF_WKT && r.GetType().size() == 1 &&
				 std::equal(r.GetPayload().begin(), r.GetPayload().end(), (const std::byte*)payload.data(), (const std::byte*)payload.data() + payload.size());
		}
		ok = ok && n == 1;
	}
	check("ndef_roundtrip", ok);
	// first byte 0xD1 = MB|ME|SR|TNF_WKT
	check("ndef_header_byte", !data.empty() && (uint8)data[0] == 0xD1);
	std::vector<std::byte> junk(3, std::byte{0xFF});
	check("tagv0_rejects_short", TagV0::FromBytes(junk) == nullptr);
}

static void test_wux()
{
	// WUX: header (32 bytes) + index table {1,0} + padding to sector 0x100 + 2 stored sectors 'A','B'
	std::vector<uint8> f(0x300, 0);
	wuxHeader_t h{};
	h.magic0 = WUX_MAGIC_0;
	h.magic1 = WUX_MAGIC_1;
	h.sectorSize = 0x100;
	h.uncompressedSize = 0x200;
	memcpy(f.data(), &h, sizeof(h));
	uint32 idx[2] = {1, 0};
	memcpy(f.data() + sizeof(h), idx, sizeof(idx));
	memset(f.data() + 0x100, 'A', 0x100);
	memset(f.data() + 0x200, 'B', 0x100);
	std::string p = fuzz_write_temp_file(f.data(), f.size(), ".wux");
	wud_t* w = wud_open(fs::path(p));
	bool ok = w && wud_isWUXCompressed(w) && wud_getWUDSize(w) == 0x200;
	if (w)
	{
		char buf[4] = {};
		ok = ok && wud_readData(w, buf, 2, 0) == 2 && buf[0] == 'B' && buf[1] == 'B';
		ok = ok && wud_readData(w, buf, 2, 0x1FE) == 2 && buf[0] == 'A';
		wud_close(w);
	}
	unlink(p.c_str());
	check("wux_sector_remap", ok);
}

static void test_prudp()
{
	prudpStreamSettings s{};
	const char* key = "ridfebb9";
	for (int i = 0; key[i]; i++) s.checksumBase += key[i];
	MD5_CTX c; MD5_Init(&c); MD5_Update(&c, key, (int)strlen(key)); MD5_Final(s.accessKeyDigest, &c);
	RC4_initCtx(&s.rc4Server, "CD&ML");
	RC4_initCtx(&s.rc4Client, "CD&ML");
	prudpPacket pkt(&s, 0xAF, 0xA1, prudpPacket::TYPE_PING, prudpPacket::FLAG_NEED_ACK, 0x12, 0x3456, 0xCAFEBABE);
	uint8 buf[512];
	sint32 len = pkt.buildData(buf, sizeof(buf));
	bool ok = len > 0 && prudpPacket::calculateSizeFromPacketData(buf, len) == len;
	if (ok)
	{
		prudpIncomingPacket in(&s, buf, len);
		ok = !in.hasError() && in.type == prudpPacket::TYPE_PING && in.src == 0xAF && in.dst == 0xA1 &&
			 in.sessionId == 0x12 && in.sequenceId == 0x3456;
		buf[len - 1] ^= 0xFF; // corrupt checksum
		prudpIncomingPacket bad(&s, buf, len);
		ok = ok && bad.hasError();
	}
	check("prudp_build_parse_roundtrip", ok);
}

static void test_filecache()
{
	const char* tmp = getenv("TMPDIR");
	fs::path p = fs::path(tmp && *tmp ? tmp : "/tmp") / fmt::format("cemu_selftest_{}.bin", getpid());
	fs::remove(p);
	bool ok = false;
	FileCache* fc = FileCache::Create(p, 7);
	if (fc)
	{
		std::string a(3000, 'x'), b = "short";
		fc->AddFile(FileCache::FileName(std::string_view("a/b.bin")), (const uint8*)a.data(), (sint32)a.size());
		fc->AddFile(FileCache::FileName(1, 2), (const uint8*)b.data(), (sint32)b.size());
		delete fc;
		fc = FileCache::Open(p, false, 7);
		std::vector<uint8> out;
		ok = fc && fc->GetFileCount() == 2 && fc->GetFile(FileCache::FileName(std::string_view("a/b.bin")), out) && out.size() == 3000 && out[2999] == 'x';
		ok = ok && fc->GetFile(FileCache::FileName(1, 2), out) && std::string(out.begin(), out.end()) == "short";
		ok = ok && !fc->HasFile(FileCache::FileName(3, 4));
		delete fc;
		FileCache* wrongVer = FileCache::Open(p, false, 8);
		ok = ok && wrongVer == nullptr;
		delete wrongVer;
	}
	fs::remove(p);
	check("filecache_roundtrip", ok);
}

static void test_ppcasm()
{
	PPCAssemblerInOut ctx{};
	ctx.virtualAddress = 0x02000000;
	bool ok = ppcAssembler_assembleSingleInstruction("li r3, 5", &ctx) && ctx.outputData.size() == 4;
	uint32 op = 0;
	if (ok)
		op = ((uint32)ctx.outputData[0] << 24) | ((uint32)ctx.outputData[1] << 16) | ((uint32)ctx.outputData[2] << 8) | ctx.outputData[3];
	check("ppcasm_li", ok && op == 0x38600005);
	PPCAssemblerInOut ctx2{};
	ctx2.virtualAddress = 0x02000000;
	ok = ppcAssembler_assembleSingleInstruction("addi r4, r3, -1", &ctx2) && ctx2.outputData.size() == 4 &&
		 ctx2.outputData[0] == 0x38 && ctx2.outputData[1] == 0x83 && ctx2.outputData[2] == 0xFF && ctx2.outputData[3] == 0xFF;
	check("ppcasm_addi_negative", ok);
	PPCDisassembledInstruction dis{};
	ppcAssembler_disassemble(0x02000000, 0x7C0802A6, &dis); // mflr r0
	check("ppcasm_disasm_mflr", std::string(ppcAssembler_getInstructionName(dis.ppcAsmCode)) == "MFLR");
	PPCAssemblerInOut bad{};
	check("ppcasm_rejects_garbage", !ppcAssembler_assembleSingleInstruction("frobnicate r99", &bad));
}

static void test_metaxml()
{
	std::string x = "<?xml version=\"1.0\" encoding=\"utf-8\"?><menu type=\"complex\" access=\"777\">"
	                "<title_version type=\"unsignedInt\" length=\"4\">32</title_version>"
	                "<title_id type=\"hexBinary\" length=\"8\">00050000101C9500</title_id>"
	                "<product_code>WUP-P-ABCD</product_code><region>4</region>"
	                "<longname_en>Hello\nWorld</longname_en><shortname_ja>JP</shortname_ja></menu>";
	std::vector<uint8> buf(x.begin(), x.end());
	ParsedMetaXml* m = ParsedMetaXml::Parse(buf.data(), buf.size());
	bool ok = m && m->GetTitleId() == 0x00050000101C9500ull && m->GetTitleVersion() == 32 &&
			  m->GetProductCode() == "WUP-P-ABCD" && m->GetLongName(CafeConsoleLanguage::EN) == "Hello World" &&
			  m->GetShortName(CafeConsoleLanguage::JA) == "JP";
	delete m;
	check("metaxml_fields", ok);
	std::string noid = "<menu><title_version>1</title_version></menu>";
	std::vector<uint8> buf2(noid.begin(), noid.end());
	check("metaxml_rejects_no_titleid", ParsedMetaXml::Parse(buf2.data(), buf2.size()) == nullptr);
}

static void test_tmd()
{
	NCrypto::TMDParser tmd;
	std::vector<uint8> tiny(16, 0);
	check("tmd_rejects_short", !tmd.parse(tiny.data(), tiny.size()));
	NCrypto::ETicketParser tik;
	check("ticket_rejects_short", !tik.parse(tiny.data(), tiny.size()));
}

int main()
{
	test_expression();
	test_ini();
	test_ndef();
	test_wux();
	test_prudp();
	test_filecache();
	test_ppcasm();
	test_metaxml();
	test_tmd();
	printf("selftest done: %d failed\n", g_fail);
	return g_fail ? 1 : 0;
}
