#pragma once
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib,"dbghelp.lib")
#include <string>
#include <map>
#include <comutil.h>
#include <algorithm>

struct SYMBOL
{
public:
	static const constexpr ULONG INVALID = 0xFFFFFFFF;
	class FIELD;
	class TYPE;
	class MODULE;

	class FIELD
	{
	public:
		bool Valid() const { return FieldId_ != INVALID; }
		TYPE GetType() const
		{
			ULONG TypeId = 0;
			if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, FieldId_, TI_GET_TYPEID, &TypeId))
			{
				return TYPE(ImageBase_, TypeId);
			}
			return TYPE(ImageBase_, INVALID);
		}
		ULONG GetOffset() const
		{
			ULONG Offset = 0;
			if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, FieldId_, TI_GET_OFFSET, &Offset))
			{
				return Offset;
			}
			return INVALID;
		}
		ULONG GetSize() const { return GetType().GetSize(); }
		ULONG GetBitPos() const
		{
			ULONG BitPos = 0;
			if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, FieldId_, TI_GET_BITPOSITION, &BitPos))
			{
				return BitPos;
			}
			return INVALID;
		}
		ULONG GetBitCount() const
		{
			ULONG64 BitCount = 0;
			if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, FieldId_, TI_GET_LENGTH, &BitCount))
			{
				return (ULONG)BitCount;
			}
			return INVALID;
		}
		ULONG GetId() const { return FieldId_; }
		std::wstring GetName() const
		{
			std::wstring result;
			PCWSTR pSymName = nullptr;
			if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, FieldId_, TI_GET_SYMNAME, &pSymName))
			{
				result = pSymName;
			}
			return result;
		}
	private:
		ULONG64 ImageBase_;
		ULONG FieldId_;
		friend class TYPE;
		friend class MODULE;
		FIELD(ULONG64 ImageBase, ULONG FieldId) :ImageBase_(ImageBase), FieldId_(FieldId) {}
	};
	class TYPE
	{
	public:
		bool Valid() const { return TypeId_ != INVALID; }
		ULONG GetSize() const
		{
			ULONG64 Size = 0;
			if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, TypeId_, TI_GET_LENGTH, &Size))
			{
				return (ULONG)Size;
			}
			return INVALID;
		}
		std::wstring GetName() const
		{
			std::wstring result;
			PCWSTR pSymName = nullptr;
			if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, TypeId_, TI_GET_SYMNAME, &pSymName))
			{
				result = pSymName;
			}
			return result;
		}
		template<typename FUN> //[&](const FIELD& Field)->bool	//返回true停止枚举
		void EnumField(FUN fun) const
		{
			//获取成员
			TI_FINDCHILDREN_PARAMS TempFp = { 0 };
			if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, TypeId_, TI_GET_CHILDRENCOUNT, &TempFp))
			{
				ULONG ChildParamsSize = sizeof(TI_FINDCHILDREN_PARAMS) + TempFp.Count * sizeof(ULONG);
				TI_FINDCHILDREN_PARAMS* pChildParams = (TI_FINDCHILDREN_PARAMS*)malloc(ChildParamsSize);
				if (pChildParams != nullptr)
				{
					ZeroMemory(pChildParams, ChildParamsSize);
					memcpy(pChildParams, &TempFp, min(sizeof(TI_FINDCHILDREN_PARAMS), ChildParamsSize));

					if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, TypeId_, TI_FINDCHILDREN, pChildParams))
					{
						for (ULONG i = pChildParams->Start; i < pChildParams->Count; i++)
						{
							if(fun(FIELD(ImageBase_, pChildParams->ChildId[i])))
								break;
						}
					}
					free(pChildParams);
				}
			}
		}
		FIELD GetField(const std::wstring& name) const
		{
			ULONG FieldId = INVALID;
			EnumField([&](const FIELD& Field)->bool
				{
					if (Field.GetName() == name)
					{
						FieldId = Field.GetId();
						return true;
					}
					return false;
				}
			);
			return FIELD(ImageBase_, FieldId);
		}
		ULONG GetId() const { return TypeId_; }
	private:
		ULONG64 ImageBase_;
		ULONG TypeId_;
		friend class FIELD;
		friend class MODULE;
		TYPE(ULONG64 ImageBase, ULONG TypeId) :ImageBase_(ImageBase), TypeId_(TypeId) {}
	};
	class MODULE
	{
	public:
		MODULE() :ImageBase_(0) {}
		bool Valid() const { return ImageBase_ != 0; }
		ULONG GetRVAByName(const std::wstring& name) const
		{
			UCHAR SymbolInfoBuf[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME] = { 0 };
			PSYMBOL_INFOW pSymbolInfo = (PSYMBOL_INFOW)SymbolInfoBuf;
			pSymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
			pSymbolInfo->MaxNameLen = MAX_SYM_NAME;
			if (SymGetTypeFromNameW(static_data().hProcess_, ImageBase_, name.c_str(), pSymbolInfo))
			{
				return (ULONG)(pSymbolInfo->Address - pSymbolInfo->ModBase);
			}
			return INVALID;
		}
		ULONG GetSizeByName(const std::wstring& name) const
		{
			UCHAR SymbolInfoBuf[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME] = { 0 };
			PSYMBOL_INFOW pSymbolInfo = (PSYMBOL_INFOW)SymbolInfoBuf;
			pSymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
			pSymbolInfo->MaxNameLen = MAX_SYM_NAME;
			if (SymGetTypeFromNameW(static_data().hProcess_, ImageBase_, name.c_str(), pSymbolInfo))
			{
				ULONG64 Length = 0;
				if (SymGetTypeInfo(static_data().hProcess_, ImageBase_, pSymbolInfo->Index, TI_GET_LENGTH, &Length))
				{
					return (ULONG)Length;
				}
			}
			return INVALID;
		}
		std::wstring GetNameByRVA(ULONG Rva) const
		{
			std::wstring result;
			UCHAR SymbolInfoBuf[sizeof(IMAGEHLP_SYMBOL64) + MAX_SYM_NAME] = { 0 };
			PIMAGEHLP_SYMBOL64 pSymbolInfo = (PIMAGEHLP_SYMBOL64)SymbolInfoBuf;
			pSymbolInfo->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
			pSymbolInfo->MaxNameLength = MAX_SYM_NAME;
			DWORD64 dwDisplacement = 0;
			if (SymGetSymFromAddr64(static_data().hProcess_, ImageBase_ + Rva, &dwDisplacement, pSymbolInfo))
			{
				_bstr_t t = pSymbolInfo->Name;
				wchar_t* pwchar = (wchar_t*)t;
				result = pwchar;
			}
			return result;
		}
		TYPE GetStructByName(const std::wstring& name) const
		{
			UCHAR buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(TCHAR)];
			memset(buffer, 0, sizeof(buffer));
			PSYMBOL_INFOW pInfo = (PSYMBOL_INFOW)buffer;
			pInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
			pInfo->MaxNameLen = sizeof(buffer) - sizeof(SYMBOL_INFO);
			if (SymGetTypeFromNameW(static_data().hProcess_, ImageBase_, name.c_str(), pInfo))
			{
				return TYPE(ImageBase_, pInfo->TypeIndex);
			}
			return TYPE(ImageBase_, INVALID);
		}
	private:
		ULONG64 ImageBase_;
		friend class FIELD;
		friend class TYPE;
		friend struct SYMBOL;
		MODULE(ULONG64 ImageBase) :ImageBase_(ImageBase) {}
	};
	static bool Initialize(PCWSTR PdbPath)
	{
		bool result = false;
		static_data().hProcess_ = (HANDLE)0x2000;
		static_data().LastImageBase_ = MODULE_SIZE;
		do
		{
			if (GetFileAttributesW(PdbPath) == INVALID_FILE_ATTRIBUTES)
			{
				if (!CreateDirectoryW(PdbPath, nullptr))
				{
					break;
				}
			}
			SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_EXACT_SYMBOLS | SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME);
			WCHAR buf[MAX_PATH] = { 0 };
			wsprintfW(buf, L"SRV*%s*https://msdl.microsoft.com/download/symbols", PdbPath);
			if (!SymInitializeW(static_data().hProcess_, buf, FALSE))
			{
				break;
			}
			result = true;
		} while (false);
		return result;
	}
	static MODULE GetModule(PCWSTR ImageFile)
	{
		DWORD64 ImageBase = 0;
		auto item = static_data().Modules_.end();
		if (GetFileAttributes(ImageFile) != INVALID_FILE_ATTRIBUTES)
		{
			std::wstring TolowerFilePath = ImageFile;
			//全部转换为小写
			std::transform(TolowerFilePath.begin(), TolowerFilePath.end(), TolowerFilePath.begin(), ::tolower);

			auto item = static_data().Modules_.find(TolowerFilePath);
			if (item == static_data().Modules_.end())
			{
				WCHAR szSymbolName[MAX_PATH] = { 0 };
				if (SymGetSymbolFileW(static_data().hProcess_, NULL, ImageFile, sfPdb, szSymbolName, MAX_PATH, szSymbolName, MAX_PATH))
				{
					if (SymLoadModuleExW(static_data().hProcess_, nullptr, ImageFile, nullptr, static_data().LastImageBase_, 0, nullptr, 0) == static_data().LastImageBase_)
					{
						ImageBase = static_data().LastImageBase_;
						static_data().LastImageBase_ += MODULE_SIZE;

						static_data().Modules_[TolowerFilePath] = MODULE(ImageBase);
						item = static_data().Modules_.find(TolowerFilePath);
					}
				}
			}
		}
		return item == static_data().Modules_.end() ? MODULE(ImageBase) : item->second;
	}
private:
	static const constexpr ULONG_PTR MODULE_SIZE = 0x1000000 * 100;
	struct static_data_t
	{
		std::map<std::wstring, MODULE> Modules_{};
		HANDLE hProcess_ = NULL;
		ULONG_PTR LastImageBase_ = 0;
	};
	static inline static_data_t& static_data() noexcept
	{
		static static_data_t data_{};
		return data_;
	}
public:
	template<typename CONTENT>
	class STRUCT
	{
	public:
		class MEMBER
		{
		public:
			MEMBER(const MEMBER& Other) noexcept = delete;
			MEMBER(MEMBER&& Other) noexcept = delete;
			MEMBER& operator=(const MEMBER& Other) noexcept = delete;
			MEMBER& operator=(MEMBER&& Other) noexcept = delete;
			template<typename T>
			T Value() const
			{
				T result{};
				int offset = Field_.GetOffset();
				if (offset != INVALID)
				{
					ULONG BitPos = Field_.GetBitPos();
					ULONG size = Field_.GetSize();
					if (BitPos != INVALID)
					{
						//位域字段
						ULONG BitCount = Field_.GetBitCount();
						ULONG64 tmpValue = 0;
						size = size > sizeof(tmpValue) ? sizeof(tmpValue) : size;
						static_data().ReadMemory_(Struct_.content_, (PUCHAR)Struct_.address_ + offset, &tmpValue, size);
						result = (T)((tmpValue >> BitPos) & ((1ULL << BitCount) - 1));
					}
					else
					{
						size = size > sizeof(T) ? sizeof(T) : size;
						static_data().ReadMemory_(Struct_.content_, (PUCHAR)Struct_.address_ + offset, &result, sizeof(result));
					}
				}
				return result;
			}
			template<typename T>
			void Value(const T& data)
			{
				ULONG offset = Field_.GetOffset();
				if (offset != INVALID)
				{
					ULONG BitPos = Field_.GetBitPos();
					ULONG size = Field_.GetSize();
					if (BitPos != INVALID)
					{
						//位域字段
						auto BitCount = Field_.GetBitCount();
						ULONG64 tmpValue = 0;
						size = size > sizeof(tmpValue) ? sizeof(tmpValue) : size;
						static_data().ReadMemory_(Struct_.content_, (PUCHAR)Struct_.address_ + offset, &tmpValue, size);
						tmpValue &= ~(((1ULL << BitCount) - 1) << BitPos);	//清空位
						tmpValue |= ((ULONG64)data) << BitPos;	//置位
						static_data().WriteMemory_(Struct_.content_, (PUCHAR)Struct_.address_ + offset, &tmpValue, size);
					}
					else
					{
						size = size > sizeof(T) ? sizeof(T) : size;
						static_data().WriteMemory_(Struct_.content_, (PUCHAR)Struct_.address_ + offset, &data, sizeof(data));
					}
				}
			}
			//pointer:是否指针类型
			STRUCT ToStruct(TYPE type, bool pointer) const
			{
				PVOID ChildAddress = nullptr;
				int Offset = Field_.GetOffset();
				if (Offset > 0)
				{
					ChildAddress = (PUCHAR)Struct_.address_ + Offset;
					if (pointer && !static_data().ReadMemory_(Struct_.content_, ChildAddress, &ChildAddress, sizeof(ChildAddress)))
					{
						ChildAddress = nullptr;
					}
				}
				return STRUCT(Struct_.content_, type, ChildAddress);
			}
			STRUCT ToStruct(bool pointer) const { return ToStruct(Field_.GetType(), pointer); }
			inline operator ULONG() const { return Value<ULONG>(); }
			inline operator ULONG64() const { return Value<ULONG64>(); }
			inline operator float() const { return Value<float>(); }
			inline operator double() const { return Value<double>(); }
			inline operator void*() const { return Value<void*>(); }
			inline MEMBER& operator =(const ULONG value) { Value(value); return*this; }
			inline MEMBER& operator =(const ULONG64 value) { Value(value); return*this; }
			inline MEMBER& operator =(const float value) { Value(value); return*this; }
			inline MEMBER& operator =(const double value) { Value(value); return*this; }
			inline MEMBER& operator =(const void* value) { Value(value); return*this; }
		private:
			STRUCT& Struct_;
			FIELD Field_;
			friend class STRUCT;
			MEMBER(STRUCT& Struct, FIELD Field) :Struct_(Struct), Field_(Field) {}
		};
		static void Initialize
		(
			bool(*ReadMemory)(CONTENT& content, PVOID address, PVOID buffer, size_t size),
			bool(*WriteMemory)(CONTENT& content, PVOID address, PVOID buffer, size_t size)
		)
		{
			static_data().ReadMemory_ = ReadMemory;
			static_data().WriteMemory_ = WriteMemory;
		}
		STRUCT(const CONTENT& content, TYPE type, PVOID address) : content_(content), type_(type), address_(address) {}
		STRUCT(const CONTENT& content, MODULE module, const std::wstring& type_name, PVOID address) : STRUCT(content, module.GetStructByName(type_name), address) {}
		STRUCT(const CONTENT& content, const std::wstring& ImageFile, const std::wstring& type_name, PVOID address) : STRUCT(content, GetModule(ImageFile), type_name, address) {}
		MEMBER GetFiled(const std::wstring& FieldName){ return MEMBER(*this, type_.GetField(FieldName)); }
		MEMBER operator[](const std::wstring& FieldName) { return GetFiled(FieldName); }
	private:
		CONTENT content_;
		TYPE type_;
		PVOID address_;
		friend class MEMBOR;
		struct static_data_t
		{
			bool(*ReadMemory_)(CONTENT& Content, PVOID address, PVOID buffer, size_t size) = nullptr;
			bool(*WriteMemory_)(CONTENT& Content, PVOID address, PVOID buffer, size_t size) = nullptr;
		};
		static inline static_data_t& static_data() noexcept
		{
			static static_data_t data_{};
			return data_;
		}
	};
};

