#pragma once

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <list>

namespace release
{
	class OBJECT
	{
	public:
		//不允许构造或复制对象
		OBJECT() = delete;
		OBJECT(const OBJECT& Other) = delete;
		template<typename T>
		inline T& value(unsigned int Offset) { return *(T*)((PUCHAR)this + Offset); }
		inline void* vfunction(unsigned int index) const noexcept { return (*(void***)this)[index]; }
		inline void vfunction(unsigned int index, void* function) noexcept { (*(void***)this)[index] = function; }
	};
	template<typename T>
	class function final
	{
		static_assert(!std::is_same_v<T, T>, "stdr::function only accepts function types as template arguments.");
	};
	template<typename _Res, typename... _ArgTypes>
	class function<_Res(_ArgTypes...)> final
	{
	private:
		union
		{
			void* address_;
			_Res(OBJECT::* object_function_)(_ArgTypes...);
			_Res(*function_)(_ArgTypes...);
		};
	public:
		inline function() noexcept : address_(nullptr) {}
		inline function(void* fun) noexcept : address_(fun) {}
		inline void*& address() noexcept { return address_; }
		inline _Res operator()(void* object_ptr, _ArgTypes...args) const { return ((*(OBJECT*)object_ptr).*object_function_)(args...); }
		inline _Res operator()(_ArgTypes...args) const { return function_(args...); }
	};
	namespace std
	{
		class string final
		{
		private:
			static constexpr size_t LocalBufferMax = (0x10 / sizeof(char)) - 1;
			union
			{
				char _Reserved[0x10];
				char _LocalBuffer[LocalBufferMax];
				char* _RemoveBuffer;
			};
			size_t _Length;
			size_t _BufferLength;
		public:
			inline string(const ::std::string& stdv = "") noexcept
			{
				_Length = stdv.length();
				_BufferLength = stdv.length() + 1;
				if (_BufferLength < LocalBufferMax)
				{
					_BufferLength = LocalBufferMax;
				}
				if (_BufferLength <= LocalBufferMax)
				{
					strcpy_s(_LocalBuffer, stdv.c_str());
				}
				else
				{
					_RemoveBuffer = new char[_BufferLength];
					strcpy_s(_RemoveBuffer, _BufferLength, stdv.c_str());
				}
			}
			inline ~string() noexcept
			{
				if (_BufferLength > LocalBufferMax)
				{
					delete[]_RemoveBuffer;
				}
			}
			inline ::std::string get() const noexcept
			{
				return ::std::string(_BufferLength > LocalBufferMax ? _RemoveBuffer : _LocalBuffer, _Length);
			}
		};

		class wstring final
		{
		private:
			static constexpr size_t LocalBufferMax = (0x10 / sizeof(wchar_t)) - 1;
			union
			{
				char _Reserved[0x10];
				wchar_t _LocalBuffer[LocalBufferMax];
				wchar_t* _RemoveBuffer;
			};
			size_t _Length;
			size_t _BufferLength;
		public:
			inline wstring(const ::std::wstring& stdv = L"") noexcept
			{
				_Length = stdv.length();
				_BufferLength = stdv.length() + 1;
				if (_BufferLength < LocalBufferMax)
				{
					_BufferLength = LocalBufferMax;
				}
				if (_BufferLength <= LocalBufferMax)
				{
					wcscpy_s(_LocalBuffer, stdv.c_str());
				}
				else
				{
					_RemoveBuffer = new wchar_t[_BufferLength];
					wcscpy_s(_RemoveBuffer, _BufferLength, stdv.c_str());
				}
			}
			inline ~wstring() noexcept
			{
				if (_BufferLength > LocalBufferMax)
				{
					delete[]_RemoveBuffer;
				}
			}
			inline ::std::wstring get() const noexcept
			{
				return ::std::wstring(_BufferLength > LocalBufferMax ? _RemoveBuffer : _LocalBuffer, _Length);
			}
		};

		template<typename T>
		class vector final
		{
		private:
			T* _BeginPtr;
			T* _EndPtr;
			T* _BufferEndPtr;
		public:
			inline vector(const ::std::vector<T>& stdv = ::std::vector<T>()) noexcept
			{
				size_t count = stdv.size();
				if (count > 0)
				{
					_BeginPtr = new T[count];
					_BufferEndPtr = _BeginPtr + count;
					for (int index = 0; index < count; index++)
					{
						_BeginPtr[index] = stdv[index];
					}
					_EndPtr = _BeginPtr + count;
				}
				else
				{
					_BeginPtr = nullptr;
					_EndPtr = nullptr;
					_BufferEndPtr = nullptr;
				}
			}
			inline ~vector() noexcept
			{
				if (_BeginPtr)
				{
					delete[] _BeginPtr;
				}
			}
			inline ::std::vector<T*> get() const noexcept
			{
				::std::vector<T*> result;
				for (auto item = _BeginPtr; item != _EndPtr; item++)
				{
					result.push_back(item);
				}
				return result;
			}
		};

		template<typename T>
		class list final
		{
		private:
			struct Data
			{
				Data* _Next;
				Data* _Prev;
				T val;
			};
			Data* d;
			size_t size;
		public:
			inline list(const ::std::list<T>& stdv = ::std::list<T>()) noexcept
			{
				size = 0;
				d = new Data();
				d->_Next = d;
				d->_Prev = d;
				for (auto& item : stdv)
				{
					Data* nd = new Data();
					nd->val = item;

					d->_Prev->_Next = nd;
					nd->_Prev = d->_Prev;
					nd->_Next = d;
					d->_Prev = nd;

					size++;
				}
			}
			inline ~list() noexcept
			{
				if (d)
				{
					while (d->_Next != d)
					{
						Data* tmp = d->_Next;
						tmp->_Next->_Prev = d;
						d->_Next = d->_Next->_Next;
						delete tmp;
					}
					delete[] d;
				}
			}
			inline ::std::list<T*> get() const noexcept
			{
				::std::list<T*> result;
				if (d)
				{
					Data* tmp = d->_Next;
					while (tmp != d)
					{
						result.push_back(&(tmp->val));
						tmp = tmp->_Next;
					}
				}
				return result;
			}
		};

		template<typename K, typename V>
		class map final
		{
		private:
			class _map :public ::std::map<K, V>
			{
			protected:
				friend class map;
				using T = ::std::_Compressed_pair<typename _map::key_compare, ::std::_Compressed_pair<typename _map::_Alnode, typename _map::_Scary_val>>;
			};
			using map_MyPair_T = typename _map::T;
			using map_Nodeptr = typename _map::_Nodeptr;
			struct Data
			{
				Data* _Left;
				Data* _Parent;
				Data* _Right;
				char _Color;
				char _Isnil;
				K firsh;
				V second;
				inline void output(::std::map<K*, V*>& result) noexcept
				{
					if (!_Isnil)
					{
						this->_Left->output(result);
						result.insert(::std::make_pair<K*, V*>(&firsh, &second));
						this->_Right->output(result);
					}
				}
			};
			Data* _Myhead;
			size_t _Mysize;
			inline Data* clone_node(map_MyPair_T* Mapptr, const map_Nodeptr Nodeptr, Data* ParentNodeptr) noexcept
			{
				if (Nodeptr->_Isnil)
				{
					return this->_Myhead;
				}
				else
				{
					Data* result = new Data();
					result->_Color = Nodeptr->_Color;
					result->_Isnil = Nodeptr->_Isnil;
					result->firsh = Nodeptr->_Myval.first;
					result->second = Nodeptr->_Myval.second;
					result->_Left = clone_node(Mapptr, Nodeptr->_Left, result);
					result->_Parent = ParentNodeptr;
					result->_Right = clone_node(Mapptr, Nodeptr->_Right, result);
					//填写左右节点
					if (Mapptr->_Myval2._Myval2._Myhead->_Left == Nodeptr)
					{
						this->_Myhead->_Left = result;
					}
					else if (Mapptr->_Myval2._Myval2._Myhead->_Right == Nodeptr)
					{
						this->_Myhead->_Right = result;
					}
					return result;
				}
			}
			inline static void free_node(Data* d) noexcept
			{
				if (!d->_Isnil)
				{
					free_node(d->_Left);
					free_node(d->_Right);
					delete d;
				}
			}
		public:
			inline map(const ::std::map<K, V>& stdv = ::std::map<K, V>()) noexcept
			{
				_Myhead = new Data();
				_Myhead->_Left = _Myhead;
				_Myhead->_Parent = _Myhead;
				_Myhead->_Right = _Myhead;
				_Myhead->_Color = 1;
				_Myhead->_Isnil = true;
				_Mysize = 0;
				if (stdv.size() > 0)
				{
					_Mysize = stdv.size();
					map_MyPair_T* Mapptr = (map_MyPair_T*)&stdv;
					_Myhead->_Parent = clone_node(Mapptr, Mapptr->_Myval2._Myval2._Myhead->_Parent, _Myhead);
				}
				//stdv._Mypair;
			}
			inline ~map() noexcept
			{
				if (_Myhead)
				{
					free_node(_Myhead->_Parent);
					delete _Myhead;
				}
			}
			inline ::std::map<K*, V*> get() const noexcept
			{
				::std::map<K*, V*> result;
				if (_Myhead)
				{
					_Myhead->_Parent->output(result);
				}
				return result;
			}
		};

		//返回的指针对象
		template<typename T>
		class xx_ptr final
		{
		private:
			struct Ref_count_base
			{
				void* vTable;
				volatile unsigned long _Uses;
				volatile unsigned long _Weaks;
			};
			struct type_t
			{
				Ref_count_base ref_;
				T object{};
			};
			T* object_ptr_;
			Ref_count_base* ref_ptr_;
		public:
			inline xx_ptr(const T& object = {}) noexcept
			{
				type_t* p = new type_t();
				p->ref_.vTable = nullptr;
				p->ref_._Uses = 999;
				p->ref_._Weaks = 888;
				p->object = object;
				object_ptr_ = &p->object;
				ref_ptr_ = &p->ref_;
			}
			inline ~xx_ptr() noexcept
			{
				if (ref_ptr_->vTable == nullptr)
				{
					delete ref_ptr_;
				}
			}
			inline T& operator*() noexcept { return *object_ptr_; }
			inline T* operator->() noexcept { return object_ptr_; }
			inline T* get() const noexcept
			{
				return object_ptr_;
			}
			inline void inc_ref() noexcept
			{
				if (ref_ptr_)
				{
					_InterlockedIncrement(&(ref_ptr_->_Uses));
				}
			}
			inline void dec_ref() noexcept
			{
				if (ref_ptr_)
				{
					_InterlockedDecrement(&(ref_ptr_->_Uses));
				}
			}
		};
	}

	namespace cef
	{
		class CefRefPtr final
		{
		public:
			void* ptr_ = nullptr;
			char undef[0x100] = { 0 };
		};
		class CefString_Unicode final
		{
		private:
			struct struct_type
			{
				wchar_t* str_;
				size_t str_length_;
			};
			void* v_table_;
			struct_type* string_;
			bool owner_;
		public:
			inline CefString_Unicode(const ::std::wstring& str = L"") noexcept
			{
				v_table_ = nullptr;
				owner_ = false;

				string_ = new struct_type();
				string_->str_length_ = str.length();
				if (string_->str_length_ > 0)
				{
					string_->str_ = new wchar_t[str.length() + 1];
					wcscpy_s(string_->str_, str.length() + 1, str.c_str());
				}
				else
				{
					string_->str_ = nullptr;
				}
			}
			inline ~CefString_Unicode() noexcept
			{
				if (string_) {
					if (string_->str_) {
						delete[] string_->str_;
					}
					delete string_;
					string_ = nullptr;
				}
			}
			inline ::std::wstring get() const noexcept
			{
				return ::std::wstring(string_->str_, string_->str_length_);
			}
		};

		class CefString_UTF8 final
		{
		private:
			struct struct_type
			{
				char* str_;
				size_t str_length_;
			};
			void* v_table_;
			struct_type* string_;
			bool owner_;
		public:
			inline CefString_UTF8(const ::std::string& str = "") noexcept
			{
				v_table_ = nullptr;
				owner_ = false;

				string_ = new struct_type();
				string_->str_length_ = str.length();
				if (string_->str_length_ > 0)
				{
					string_->str_ = new char[str.length() + 1];
					strcpy_s(string_->str_, str.length() + 1, str.c_str());
				}
				else
				{
					string_->str_ = nullptr;
				}
			}
			inline ~CefString_UTF8() noexcept
			{
				if (string_) {
					if (string_->str_) {
						delete[] string_->str_;
					}
					delete string_;
					string_ = nullptr;
				}
			}
			inline ::std::string get() const noexcept
			{
				return ::std::string(string_->str_, string_->str_length_);
			}
		};
	}

	namespace qt5
	{
		template<typename T>
		class QVector
		{
		private:
			struct QArrayData
			{
				uint32_t ref_atomic;
				uint32_t size;
				uint32_t alloc;
				uint32_t Reseved;
				size_t offset;
				T data[1];
			};
			QArrayData* d;
		public:
			inline QVector(const ::std::vector<T>& stdv = ::std::vector<T>()) noexcept
			{
				uint32_t count = (uint32_t)stdv.size();
				size_t buffer_size = sizeof(QArrayData) + sizeof(T) * count;
				d = (QArrayData*)new char[buffer_size];
				memset(d, 0, buffer_size);
				d->ref_atomic = 1;
				d->size = count;
				d->alloc = count + 1;
				d->offset = sizeof(QArrayData) - sizeof(T);
				for (uint32_t i = 0; i < count; i++)
				{
					d->data[i] = stdv[i];
				}
			}
			inline ~QVector() noexcept
			{
				delete d;
			}
			inline ::std::vector<T*> get() const noexcept
			{
				::std::vector<T*> result;
				for (uint32_t i = 0; i < d->size; i++)
				{
					result.push_back(d->data + i);
				}
				return result;
			}
		};
		class QString final :protected QVector<wchar_t>
		{
		public:
			inline QString(const ::std::wstring& str = L"") noexcept
				:QVector(::std::vector<wchar_t>(str.begin(), str.end()))
			{

			}
			inline ::std::wstring get() const noexcept
			{
				auto v = QVector::get();
				return ::std::wstring(*v.begin(), v.size());
			}
		};

		template<typename T>
		class QList final
		{
		private:
			struct Data
			{
				uint32_t ref;
				int alloc, begin, end;
				T array[1];
			};
			Data* d;
		public:
			inline QList(const ::std::list<T>& stdv = ::std::list<T>()) noexcept
			{
				int count = (int)stdv.size();
				d = (Data*)new char[sizeof(Data) + sizeof(T) * count];
				d->ref = 1;
				d->alloc = count + 1;
				d->begin = 0;
				d->end = count;
				int index = 0;
				for (auto& item : stdv)
				{
					d->array[index++] = item;
				}
			}
			inline ~QList() noexcept
			{
				delete d;
			}
			inline ::std::list<T*> get() const noexcept
			{
				::std::list<T*> result;
				for (int i = d->begin; i < d->end; i++)
				{
					result.push_back(d->array + i);
				}
				return result;
			}
		};

		template<typename K, typename V>
		class QMap final
		{
		private:
			class _map :public ::std::map<K, V>
			{
			protected:
				friend class QMap;
				using T = ::std::_Compressed_pair<typename _map::key_compare, ::std::_Compressed_pair<typename _map::_Alnode, typename _map::_Scary_val>>;
			};
			using map_MyPair_T = typename _map::T;
			using map_Nodeptr = typename _map::_Nodeptr;

			struct QMapNode
			{
				static constexpr size_t Mask = 3;
				size_t p;
				struct QMapNode* left;
				struct QMapNode* right;
				K k;
				V v;
				inline void output(::std::map<K*, V*>& result) noexcept
				{
					if (this->left)
					{
						this->left->output(result);
					}
					result.insert(::std::make_pair<K*, V*>(&k, &v));
					if (this->right)
					{
						this->right->output(result);
					}
				}
			};
			struct QMapData
			{
				uint32_t ref_atomic;
				int size;
				QMapNode data;
				QMapNode* mostLeftNode;
			};
			QMapData* d;
			inline QMapNode* clone_node(map_MyPair_T* Mapptr, const map_Nodeptr Nodeptr, QMapNode* ParentNodeptr) noexcept
			{
				if (Nodeptr->_Isnil)
				{
					return nullptr;
				}
				else
				{
					QMapNode* result = new QMapNode();
					result->k = Nodeptr->_Myval.first;
					result->v = Nodeptr->_Myval.second;
					result->left = clone_node(Mapptr, Nodeptr->_Left, result);
					result->p = (size_t)ParentNodeptr | Nodeptr->_Color;
					result->right = clone_node(Mapptr, Nodeptr->_Right, result);
					//填写左节点
					if (Mapptr->_Myval2._Myval2._Myhead->_Left == Nodeptr)
					{
						this->d->mostLeftNode = result;
					}
					return result;
				}
			}
			inline static void free_node(QMapNode* d) noexcept
			{
				if (d)
				{
					free_node(d->left);
					free_node(d->right);
					delete d;
				}
			}
		public:
			inline QMap(const ::std::map<K, V>& stdv = ::std::map<K, V>()) noexcept
			{
				d = new QMapData();
				d->ref_atomic = 1;
				d->size = 0;
				d->data.p = 0;
				d->data.left = nullptr;
				d->data.right = nullptr;
				if (stdv.size() > 0)
				{
					d->size = (int)stdv.size();
					map_MyPair_T* Mapptr = (map_MyPair_T*)&stdv;
					d->data.left = clone_node(Mapptr, Mapptr->_Myval2._Myval2._Myhead->_Parent, &(d->data));
				}
			}
			inline ~QMap() noexcept
			{
				if (d)
				{
					free_node(d->data.left);
					//data的左节点就是root
					//free_node(d->data.right);
					delete d;
				}
			}
			inline ::std::map<K*, V*> get() const noexcept
			{
				::std::map<K*, V*> result;
				if (d)
				{
					if (d->data.left)
					{
						d->data.left->output(result);
					}
					//data的左节点就是root
					/*
					if (d->data.right)
					{
						d->data.right->output(result);
					}
					*/
				}
				return result;
			}
		};
	}
}