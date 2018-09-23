#include "stdafx.h"
#include "PaydayLua/InGameWin32.h"
#include "FunctionHooker.h"
#include "ProcessSearcher.h"
#include "TempDetour.h"
#include "Utility.h"

using namespace Olipro;

InGameHandling* InGameHandling::self = nullptr;
decltype(InGameHandling::tGameTick) InGameHandling::tGameTick;
decltype(InGameHandling::tNewState) InGameHandling::tNewState;
decltype(InGameHandling::tCloseState) InGameHandling::tCloseState;
decltype(InGameHandling::tlua_setfield) InGameHandling::tlua_setfield;

InGameHandling::InGameHandling(	decltype(ProcessGameTick) onTick,
								decltype(ProcessNewState) onNew,
								decltype(ProcessCloseState) onClose) :
	ProcessGameTick(onTick), ProcessNewState(onNew),
	ProcessCloseState(onClose), functions(LoadSignatures())
{
	ProcessSearcher s;
	FunctionHooker hook;
	auto doGameTick = s.CalcFunction<decltype(*tGameTick)&>(
		"\xE8\x00\x00\x00\x00\xFF\x74\x24\x7C\xFF\x74\x24\x7C", '\x00', 1);	// E8 ? ? ? ? FF 74 24 7C FF 74 24 7C 
	hook.Attach(&doGameTick, &HookDoGameTick, &tGameTick);
	auto newState = &functions.luaL_newstate;
	hook.Attach(&newState, &HookNewState, &tNewState);
	auto closeState = &functions.lua_close;
	hook.Attach(&closeState, &HookLuaClose, &tCloseState);
}

InGameHandling& InGameHandling::GetInstance(decltype(ProcessGameTick) onTick,
	decltype(ProcessNewState) onNew, decltype(ProcessCloseState) onClose)
{
	static InGameHandling ret{ onTick, onNew, onClose };
	self = &ret;
	return ret;
}

InGameHandling& InGameHandling::GetInstance()
{
	if (!self)
		throw std::logic_error("Attempt to GetInstance before initialisation");
	return *self;
}

void InGameHandling::OnGameTick(lua_State* L, const char* op)
{
	GetInstance().ProcessGameTick(L, op);
}

void InGameHandling::HookNewState(lua_State** L, int edx, int a, int b, int c)
{
	auto self = GetInstance();
	{
		auto setFieldDetour = reinterpret_cast<FunctionHooker::UnsafePtr*>(
			&HookLuaSetField);
		auto setField = &self.functions.lua_setfield;
		TempDetour d{ &setField, setFieldDetour, &tlua_setfield };
		tNewState(L, edx, a, b, c);
	}
	self.ProcessNewState(*L);
}

void InGameHandling::OnLuaSetField(lua_State* L, int tbl, const char* k)
{
	const std::string name = k;
	if (tbl == LUA_GLOBALSINDEX && (name == "xpcall" || name == "pcall"))
		Lua::lua_settop(L, -2);
	else
		SafeCall(tlua_setfield, L, tbl, k);
}

void InGameHandling::HookLuaClose(lua_State* L)
{
	auto self = GetInstance();
	self.ProcessCloseState(L);
	self.tCloseState(L);
}

InGameHandling::InGameFunctionSignatures InGameHandling::LoadSignatures()
{
	using IGFS = InGameFunctionSignatures;
	ProcessSearcher s;
	return {
		s.FindFunction<decltype(IGFS::lua_checkstack)>(
			"\x8B\x54\x24\x08\x81\xFA")
		, *s.CalcFunction<decltype(IGFS::lua_close)>(
			"\xE8\x00\x00\x00\x00\x8B\x3D\x00\x00\x00\x00\x59\xE8", '\x00', 1)
		, *s.CalcFunction<decltype(IGFS::lua_createtable)>(
			"\xE8\x00\x00\x00\x00\x6A\xFF\xFF\x36", '\x00', 1)
		, *s.CalcFunction<decltype(IGFS::lua_getfield)>(
			"\xE8\x00\x00\x00\x00\x33\xDB\x88\x5D\xFC", '\x00', 1)
		, s.FindFunction<decltype(IGFS::lua_getinfo)>(
			"\x53\x55\x56\x8B\xDA\x8B\x54\x24\x10\x57\x8B\xF1\x33\xFF\x33\xC9")	// ?
		, s.FindFunction<decltype(IGFS::lua_gettable)>(
			"\x56\x8B\xF1\xE8\x88\xF8\xFF\xFF\x8B\x56\x08\x83\xC2\xF8\x52\x52") // ? prolly optimized out
		, s.FindFunction<decltype(IGFS::lua_newuserdata)>(
			"\x51\x56\x8B\xF1\x57\x8B\x4E\x10\x8B\xFA\x8B\x41\x48\x85\xC0\x74")	// ? prolly optimized out
		, *s.CalcFunction<decltype(IGFS::lua_objlen)>(
			"\xE8\x00\x00\x00\x00\x8B\x55\x04\x8B\xCA", '\x00', 1)
		, s.FindFunction<decltype(IGFS::lua_pcall)>(
			"\x8B\x54\x24\x04\x8B\x4C\x24\x10")
		, *s.CalcFunction<decltype(IGFS::lua_pushcclosure)>(
			"\xE8\x00\x00\x00\x00\x8B\x4D\x08\x83\xC4\x14", '\x00', 1)
		, *s.CalcFunction<decltype(IGFS::lua_pushlstring)>(
			"\xE8\x00\x00\x00\x00\x83\xC4\x0C\xEB\xE2", '\x00', 1)
		, *s.CalcFunction<decltype(IGFS::lua_rawgeti)>(
			"\xE8\x00\x00\x00\x00\x6A\xFF\x6A\xFE", '\x00', 1)
		, s.FindFunction<decltype(IGFS::lua_rawset)>(
			"\x51\x53\x55\x56\x57\x8B\xF1\xE8\x34\xF6\xFF\xFF\x8B\x5E\x08\x8B") // ?
		, s.CalcFunction<decltype(IGFS::lua_rawseti)>(
			"\xE8\x00\x00\x00\x00\xFF\x74\x24\x20\x55", '\x00', 1)
		, s.FindFunction<decltype(IGFS::lua_resume)>(
			"\x51\x53\x56\x8B\xF1\x8A\x46\x06\x3C\x01\x74\x28\x84\xC0\x74\x0E")	// ?
		, s.CalcFunction<decltype(IGFS::lua_setfield)>(
			"\xE8\x00\x00\x00\x00\x88\x5D\xF8", '\x00', 1)
		, s.FindFunction<decltype(IGFS::lua_setmetatable)>(
			"\x56\x57\x8B\xF1\xE8\x27\xF5\xFF\xFF\x8B\x4E\x08\x8B\xD0\x83\x79") // couldn't find ref to it looks opt.
		, s.CalcFunction<decltype(IGFS::lua_settop)>(
			"\xE8\x00\x00\x00\x00\x8B\x5D\x58", '\x00', 1)
		, s.CalcFunction<decltype(IGFS::lua_tolstring)>(
			"\xE8\x00\x00\x00\x00\xDD\x44\x24\x58", '\x00', 1)
		, s.FindFunction<decltype(IGFS::luaC_fullgc)>(
			"\x56\x57\x8B\xF9\x8B\x77\x10\x80\x7E\x15\x01") // NOT EVEN EXISTENT IN LUAJIT
		, s.FindFunction<decltype(IGFS::luaC_step)>(
			"\x51\x53\x55\x56\x8B\xE9\x57\x8B\x7D\x10\x8B\x47\x5C\x8D\x1C\x80") // existent can't find xref
		, s.FindFunction<decltype(IGFS::luaD_call)>(
			"\x55\x8B\xEC\x83\xE4\xF8\x56\x8B\xF1\xB9\xC8\x00\x00\x00\x66\xFF") // no xref string inside not referenced
		, s.FindFunction<decltype(IGFS::luaD_protectedparser)>(
			"\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x14\x8B\x45\x08\x53\x56\x8B\xF1") // can't find good xref
		, s.FindFunction<decltype(IGFS::luaE_newthread)>(
			"\x55\x8B\xEC\x83\xE4\xF8\x51\x53\x56\x57\x6A\x64\x8B\xF1\x6A\x00") // not existent in luajit
		, s.FindFunction<decltype(IGFS::luaG_errormsg)>(
			"\x56\x8B\xF1\x57\x8B\x46\x60\x85\xC0\x74\x66\x8B\x7E\x20\x03\xF8") // doesn't seem to be shipped either (minilua.c)
		, s.FindFunction<decltype(IGFS::luaH_getnum)>(
			"\x51\x57\x8B\xF9\x8D\x42\xFF\x3B\x47\x1C\x73\x0C\x8B\x47\x0C\x5F") // nah m8
		, s.CalcFunction<decltype(IGFS::luaL_error)>(
			"\xE8\x00\x00\x00\x00\x83\xC4\x10\xEB\x1D",'\x00', 1)				// unsure
		, s.CalcFunction<decltype(IGFS::luaL_findtable)>(
			"\xE8\x00\x00\x00\x00\x53\x6A\xFF",'\x00', 1)
		, s.FindFunction<decltype(IGFS::luaL_loadbuffer)>(
			"\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x20\x8B\x45\x08\x89\x44\x24\x04")	// optimized out only find calls to lua_load ([( E8 ? ? ? ? FF 74 24 24 8B E8 ) + 1])
		, s.FindFunction<decltype(IGFS::luaL_loadfile)>(
			"\x55\x8B\xEC\x83\xE4\xF8\x81\xEC\x20\x02\x00\x00\x53\x55\x56\x57") // luaL_loadfilex ([(E8 ? ? ? ? 83 C4 0C 85 C0 75 19 50) + 1]
		, s.CalcFunction<decltype(IGFS::luaL_newstate)>(
			"\xE8\x00\x00\x00\x00\x38\x5D\x14", '\x00', 1)
		, s.CalcFunction<decltype(IGFS::luaO_pushvfstring)>(
			"\xE8\x00\x00\x00\x00\x8B\x4E\x10\x6A\x00", '\x00', 1)
		, s.FindFunction<decltype(IGFS::luaV_settable)>(
			"\x83\xEC\x08\x53\x55\x56\x8B\xEA\x57\x89\x6C\x24\x10\x8B\xD9\xC7") // might be still there too tired to find xref
	};
}
