#pragma once
#include <iomanip>

namespace Olipro
{
	class ProcessSearcher {
		LPBYTE moduleBase;
		size_t moduleSize;

	public:
		ProcessSearcher()
		{
			moduleBase = reinterpret_cast<LPBYTE>(GetModuleHandle(nullptr));

			if (moduleBase)
			{
				auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(
					moduleBase);

				if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
				{
					auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
						moduleBase + dosHeader->e_lfanew);
					moduleBase = moduleBase +
						ntHeaders->OptionalHeader.BaseOfCode;
					moduleSize = ntHeaders->OptionalHeader.SizeOfCode - 1;
				}
			}
		}

		template <typename T>
		T FindFunction(	T& obj, const std::string& signature,
						const std::string& predicate)
		{
			auto needle = reinterpret_cast<const BYTE* const>(
				signature.c_str());
			auto predFunc = [w = predicate[0]](const BYTE& a, const BYTE& b) {
				return b == w || a == b;
			};
			auto result = std::search(moduleBase, moduleBase + moduleSize,
				needle, needle + signature.length(), predFunc);
			obj = reinterpret_cast<T>(result != (moduleBase + moduleSize) ?
				result : nullptr);
			return obj;
		}

		template <typename T>
		T FindFunction(T& obj, const std::string& signature)
		{
			auto needle = reinterpret_cast<const BYTE* const>(
				signature.c_str());
			auto result = std::search(moduleBase, moduleBase + moduleSize,
				needle, needle + signature.length());
			obj = reinterpret_cast<T>(result != (moduleBase + moduleSize) ?
				result : nullptr);
			return obj;
		}

		template <typename T>
		T& FindFunction(const std::string& signature)
		{
			auto needle = reinterpret_cast<const BYTE* const>(
				signature.c_str());
			auto result = std::search(moduleBase, moduleBase + moduleSize,
				needle, needle + signature.length());
			auto ret = result != (moduleBase + moduleSize) ? result : nullptr;
			if (ret == nullptr) {
				std::ofstream file{ "missingsigs.txt", std::ios::app };
				file << "not found: " << typeid(T).name();
				for (auto i : signature)
					file << std::hex << std::setfill('0') << std::setw(2)
					<< static_cast<unsigned int>(static_cast<unsigned char>(i)) << " ";
				file << "\n";
			}
			return *reinterpret_cast<std::add_pointer_t<T>>(ret);
		}


		uint32_t findPattern(const std::string& pattern, const char pred, DWORD offset)
		{
			bool found = false;

			for (auto i = moduleBase; i < moduleBase + moduleSize - pattern.length(); i++)
			{
				found = true;

				for (unsigned int idx = 0; idx < pattern.length(); idx++)
				{
					if (pattern[idx] != pred && pattern[idx] != *(char*)(i + idx))
					{
						found = false;
						break;
					}
				}

				if (found)
					return reinterpret_cast<uint32_t>(i + offset);
			}
			return 0;
		}

		template <typename T>
		T& CalcFunction(const std::string& signature,
			const char predicate,
			const uint32_t offset = 0)
		{
			auto sigFind = findPattern(signature, predicate, offset);
			uint32_t foundFunc = 0;
			if (sigFind != 0)
			{
				foundFunc = sigFind + *reinterpret_cast<int32_t*>(sigFind) + 4;
			}

			return *reinterpret_cast<std::add_pointer_t<T>>(foundFunc);
		}
	};
}
