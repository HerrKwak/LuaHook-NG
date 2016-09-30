#pragma once
#include "LuaInterface.h"
#include <functional>
#include <functional>
#include <memory>
#include <string>
#include "Lua.h"

#ifndef LUAHOOKNG_EXPORTS
#pragma comment (lib, "LuaHook-NG.lib")
#define EXTERNAL __declspec(dllimport)
#endif

namespace Olipro {
	class LuaGameImpl;

	class EXTERNAL LuaGame final {
#pragma warning(suppress: 4251)
		const std::unique_ptr<LuaGameImpl> impl;

	public:
		struct CallbackArgs {
			const std::function<void(lua_State*, LuaInterface&)> onTick;
			const std::function<void(lua_State*, LuaInterface&)> onNew;
			const std::function<void(lua_State*, LuaInterface&)> onClose;
			const std::function<void(lua_State*, LuaInterface&,
											const std::string&)> onRequire;
		};

		LuaGame(const CallbackArgs&);
		~LuaGame();
		LuaGame& operator<<(const std::string&);
	};
}

extern "C" EXTERNAL void LuaHookNG(); //dummy function for forcing linkage.
