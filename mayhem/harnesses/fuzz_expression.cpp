// TExpressionParser (src/Cemu/ExpressionParser/ExpressionParser.h): the tokenizer / shunting-yard
// evaluator used for graphic pack preset values and patches.txt expressions. Errors are reported by
// throwing std::runtime_error, which Cemu's callers catch (GraphicPack2::ParseRule etc.), so the
// harness catches exactly that.
#include "Common/precompiled.h"
#include "Cemu/ExpressionParser/ExpressionParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	std::string expr((const char*)data, size);
	{
		TExpressionParser<double> ep;
		// constants as graphic packs define them ($width/$height presets and custom vars)
		ep.AddConstant("width", 1280.0);
		ep.AddConstant("height", 720.0);
		ep.AddConstant("$scale", 2.0);
		ep.AddConstant("$fps", "60");
		try { volatile double v = ep.Evaluate(expr); (void)v; } catch (const std::exception&) {}
		(void)ep.IsConstantExpression(expr);
	}
	{
		TExpressionParser<sint64> ep;
		ep.AddConstant("base", (sint64)0x02000000);
		try { volatile sint64 v = ep.Evaluate(expr); (void)v; } catch (const std::exception&) {}
	}
	return 0;
}
