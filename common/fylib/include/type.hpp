#pragma once

#ifndef BUG_CHECK
#define BUG_CHECK(Expression,info) if(Expression){__debugbreak();}
#endif // !BUG_CHECK

struct TYPE
{
private:
    struct static_data_t
    {
        void* (*malloc_)(size_t) = nullptr;
        void (*free_)(void*) = nullptr;
    };
    static inline static_data_t& static_data() noexcept
    {
        static static_data_t data_{};
        return data_;
    }
public:
	static inline bool Initialize(void* (*malloc)(size_t), void (*free)(void*))
	{
		static_data().malloc_ = malloc;
		static_data().free_ = free;
		return true;
	}
#pragma region 基类
private:
	class BASE
	{
	public:
		inline void* operator new(size_t size) noexcept {
            return static_data().malloc_ ? static_data().malloc_(size) : nullptr;
		}
		inline void operator delete(void* ptr) noexcept {
            if(static_data().free_)
			    static_data().free_(ptr);
		}
	};
#pragma endregion
private:
	template <typename U>
	struct HASEQUAL
	{
	private:
		template <typename T, bool (T::*)(const T&) = &T::operator>, bool (T::*)(const T&) = &T::operator<>
		static constexpr bool CHECK_(T*) { return true; }
		static constexpr bool CHECK_(...) { return false; }
	public:
		static constexpr bool CHECK() { return CHECK_(static_cast<U*>(nullptr)); }
	};
	template <typename U, typename K>
	struct HASEQUALEX
	{
	private:
		template <typename T, bool (T::*)(const K&) = &T::operator>, bool (T::*)(const K&) = &T::operator<>
		static constexpr bool CHECK_(T*) { return true; }
		static constexpr bool CHECK_(...) { return false; }
	public:
		static constexpr bool CHECK() { return CHECK_(static_cast<U*>(nullptr)); }
	};
public:
    template<typename T>
    class LIST
    {
    public:
        class NODE : private LIST, public BASE
        {
        public:
            //如果定义静态或全局NODE会出现.CRT节
            inline NODE() noexcept :_Data() {}
            inline NODE(const T& Other) noexcept :_Data(Other) {}
            inline NODE(const LIST<T>::NODE& Other) noexcept :NODE(Other._Data) {}
            static inline NODE* ForBuffer(void* Buffer) noexcept {
                NODE* pThis = (NODE*)(LIST::ForBuffer(Buffer));
                if (!pThis) {
                    return nullptr;
                }
                memset(&(pThis->_Data), 0, sizeof(pThis->_Data));
                return pThis;
            }
            inline void Remove() noexcept {
                BUG_CHECK((_pLast == this || _pNext == this), "Wrong NODE\n");
                this->_pLast->_pNext = this->_pNext;
                this->_pNext->_pLast = this->_pLast;
                this->_pNext = this->_pLast = this;
            }
            inline T& operator*() noexcept {
                return _Data;
            }
            inline T* operator->() noexcept {
                return &_Data;
            }
        private:
            friend class LIST;
            T _Data;
        };
        class ITER
        {
        public:
            inline NODE* operator*() noexcept {
                return DataPtr();
            }
            inline NODE& operator->() noexcept {
                return *DataPtr();
            }
            inline bool operator==(const ITER& Other) noexcept {
                return _Cur == Other._Cur;
            }
            inline bool operator!=(const ITER& Other) noexcept {
                return !(*this == Other);
            }
            inline ITER& operator++() noexcept {
                _Cur = _NextCur;
                UpdateCache();
                return *this;
            }
            inline ITER& operator--() noexcept {
                _Cur = _LastCur;
                UpdateCache();
                return *this;
            }
            inline NODE* DataPtr() noexcept {
                return (NODE*)_Cur;
            }
        private:
            friend class LIST;
            inline ITER(LIST* Cur) noexcept :_Cur(Cur) {
                UpdateCache();
            };
            inline void UpdateCache() noexcept {
                _NextCur = _Cur->_pNext;
                _LastCur = _Cur->_pLast;
            }
            LIST* _Cur;
            //防止迭代过程中删除，缓存前后节点
            LIST* _NextCur, * _LastCur;
        };
        inline LIST() noexcept = default;
        inline LIST(const LIST& Other) noexcept = delete;
        static inline LIST* ForBuffer(void* Buffer) noexcept {
            LIST* pThis = (LIST*)Buffer;
            if (!pThis) {
                return nullptr;
            }
            pThis->_pNext = pThis->_pLast = pThis;
            return pThis;
        }
        inline bool Empty() const noexcept {
            return _pNext == this;
        }
        inline NODE* PushFront(NODE* pNode) noexcept {
            BUG_CHECK((pNode->_pLast != pNode || pNode->_pNext != pNode), "Wrong NODE\n");
            pNode->_pLast = this;
            pNode->_pNext = this->_pNext;
            this->_pNext->_pLast = pNode;
            this->_pNext = pNode;
            return pNode;
        }
        inline NODE* PushBack(NODE* pNode) noexcept {
            BUG_CHECK((pNode->_pLast != pNode || pNode->_pNext != pNode), "Wrong NODE\n");
            pNode->_pNext = this;
            pNode->_pLast = this->_pLast;
            this->_pLast->_pNext = pNode;
            this->_pLast = pNode;
            return pNode;
        }
        inline NODE* PopFront() noexcept {
            if (Empty()) {
                return nullptr;
            }
            NODE* result = reinterpret_cast<NODE*>(this->_pNext);
            result->Remove();
            return result;
        }
        inline NODE* PopBack() noexcept {
            if (Empty()) {
                return nullptr;
            }
            NODE* result = reinterpret_cast<NODE*>(this->_pLast);
            result->Remove();
            return result;
        }
        inline NODE* SeeFront() noexcept {
            if (Empty()) {
                return nullptr;
            }
            return reinterpret_cast<NODE*>(this->_pNext);
        }
        inline NODE* SeeBack() noexcept {
            if (Empty()) {
                return nullptr;
            }
            return reinterpret_cast<NODE*>(this->_pLast);
        }
        inline LIST& operator<<(NODE* pNode)noexcept {
            PushBack(pNode);
            return *this;
        }
        inline ITER begin() noexcept {
            return ITER(_pNext);
        }
        inline ITER end() noexcept {
            return ITER(this);
        }
        inline ITER rbegin() noexcept {
            return ITER(_pLast);
        }
        inline ITER rend() noexcept {
            return ITER(this);
        }
    protected:
        LIST* _pNext = this;
        LIST* _pLast = this;
    };

    template<typename T, int MAXSIZE, bool CanCover>
    class FIXEDARRAY
    {
    public:
        class ITER
        {
        public:
            inline T& operator*() noexcept {
                return *DataPtr();
            }
            inline T* operator->() noexcept {
                return DataPtr();
            }
            inline bool operator==(const ITER& Other) noexcept {
                return _Cur == Other._Cur;
            }
            inline bool operator!=(const ITER& Other) noexcept {
                return !(*this == Other);
            }
            inline ITER& operator++() noexcept {
                if (!_Remove) {
                    ++_Cur;
                }
                if (_Cur > _Array.Size()) {
                    _Cur = 0;
                }
                _Remove = false;
                return *this;
            }
            inline ITER& operator--() noexcept {
                --_Cur;
                _Remove = false;
                return *this;
            }
            inline T* DataPtr() noexcept {
                return &_Array._Items[(_Array._BeginPos + _Cur) % MAXSIZE];
            }
            //移除当前元素
            inline void Remove() noexcept {
                BUG_CHECK(_Remove, "Repeat removal\n");
                _Array.RemoveAt((_Array._BeginPos + _Cur) % MAXSIZE);
                //调整位置，为下一次迭代做准备
                _Remove = true;
            }
        private:
            inline ITER(FIXEDARRAY& Array, int Cur) noexcept :_Array(Array), _Cur(Cur), _Remove(false) {}
            friend class FIXEDARRAY;
            int _Cur;
            // 移除状态
            bool _Remove;
            FIXEDARRAY& _Array;
        };
        inline FIXEDARRAY() noexcept = default;
        inline FIXEDARRAY(const FIXEDARRAY& Other) noexcept = delete;
        static inline FIXEDARRAY* ForBuffer(void* Buffer) noexcept {
            FIXEDARRAY* pThis = (FIXEDARRAY*)Buffer;
            if (!pThis) {
                return nullptr;
            }
            pThis->_BeginPos = pThis->_EndPos = pThis->_LossCount = 0;
            pThis->_Empty = true;
            memset(pThis->_Items, 0, sizeof(pThis->_Items));
            return pThis;
        }
        inline bool Empty() const noexcept {
            return _Empty;
        }
        inline unsigned int GetAndCleanLossCount() noexcept {
            int result = _LossCount;
            _LossCount = 0;
            return result;
        }
        inline T& PushFront(T Data) noexcept {
            if (!_Empty && _BeginPos == _EndPos)
            {
                BUG_CHECK(!CanCover, "Array is full\n");
                //干掉最后面元素
                if (--_EndPos < 0) {
                    _EndPos += MAXSIZE;
                }
                _LossCount++;
            }
            _Items[_BeginPos] = Data;
            T& Result = _Items[_BeginPos];
            if (--_BeginPos < 0) {
                _BeginPos += MAXSIZE;
            }
            _Empty = false;
            return Result;
        }
        inline T& PushBack(T Data) noexcept {
            if (!_Empty && _BeginPos == _EndPos) {
                BUG_CHECK(!CanCover, "Array is full\n");
                //干掉最前面元素
                if (++_BeginPos >= MAXSIZE) {
                    _BeginPos = 0;
                }
                _LossCount++;
            }
            if (++_EndPos >= MAXSIZE) {
                _EndPos = 0;
            }
            _Items[_EndPos] = Data;
            _Empty = false;
            return _Items[_EndPos];
        }
        inline T PopFront() noexcept
        {
            T result = {};
            BUG_CHECK(_Empty, "Array is empty\n");
            if (++_BeginPos >= MAXSIZE) {
                _BeginPos = 0;
            }
            result = _Items[_BeginPos];
            _Empty = _BeginPos == _EndPos;
            return result;
        }
        inline T PopBack() noexcept
        {
            T result = {};
            BUG_CHECK(_Empty, "Array is empty\n");
            result = _Items[_EndPos--];
            if (_EndPos < 0)
                _EndPos = MAXSIZE - 1;
            _Empty = _BeginPos == _EndPos;
            return result;
        }
        inline T& SeeFront() noexcept {
            T result = {};
            BUG_CHECK(_Empty, "Array is empty\n");
            int Pos = _BeginPos + 1;
            if (Pos >= MAXSIZE) {
                Pos = 0;
            }
            return _Items[Pos];
        }
        inline T& SeeBack() noexcept {
            T result = {};
            BUG_CHECK(_Empty, "Array is empty\n");
            return _Items[_EndPos];
        }
        inline int Size() const noexcept {
            if (_Empty) {
                return 0;
            }
            int Result = _EndPos - _BeginPos;
            if (_EndPos <= _BeginPos) {
                Result += MAXSIZE;
            }
            return Result;
        }
        inline FIXEDARRAY& operator<<(T Data)noexcept {
            PushFront(Data); return *this;
        }
        inline T operator>>(T Data)noexcept {
            return PopFront();
        }
        //因为_BeginPos数据无效,所以最大元素是Size(),最小元素是0
        inline ITER begin() noexcept {
            return ITER(*this, _Empty ? 0 : 1);
        }
        inline ITER end() noexcept {
            return ITER(*this, 0);
        }
        inline ITER rbegin() noexcept {
            return ITER(*this, Size());
        }
        inline ITER rend() noexcept {
            return ITER(*this, 0);
        }
    private:
        friend class ITER;
        int _BeginPos = 0;  //无效数据
        int _EndPos = 0;    //有效数据
        bool _Empty = true;
        unsigned int _LossCount = 0;
        T _Items[MAXSIZE] = { 0 };
        //移除指定位置的元素
        inline void RemoveAt(int Index) noexcept {
            if (_Empty) {
                return;
            }
            if (_EndPos > _BeginPos) {
                BUG_CHECK((Index <= _BeginPos || Index > _EndPos), "Invalid Index\n");
                memmove(_Items + Index, _Items + Index + 1, (_EndPos - Index) * sizeof(_Items[0]));
            }
            else {
                int TmpEnd = _EndPos + MAXSIZE;
                int TmpPos = Index <= _EndPos ? Index + MAXSIZE : Index;
                BUG_CHECK(TmpPos <= _BeginPos || TmpPos > TmpEnd, "Invalid Index\n");
                memmove(_Items + Index, _Items + Index + 1, (MAXSIZE - Index - 1) * sizeof(_Items[0]));
                if (_EndPos >= 0) {
                    _Items[MAXSIZE - 1] = _Items[0];
                    memmove(_Items + 0, _Items + 1, (_EndPos) * sizeof(_Items[0]));
                }
            }
            --_EndPos;
            if (_EndPos < 0) {
                _EndPos += MAXSIZE;
            }
            _Empty = _BeginPos == _EndPos;
        }
    };

    template<typename T>
    class RBTREE
    {
    public:
        class NODE :public RBTREE, public BASE
        {
        public:
            //如果定义静态或全局NODE会出现.CRT节
            inline NODE() noexcept :_Data() {};
            inline NODE(const T& Other) noexcept :_Data(Other) {}
            inline NODE(const RBTREE<T>::NODE& Other) noexcept :NODE(Other._Data) {}
            static inline NODE* ForBuffer(void* Buffer) noexcept {
                NODE* pThis = (NODE*)(RBTREE::ForBuffer(Buffer));
                if (!pThis) {
                    return nullptr;
                }
                memset(&(pThis->_Data), 0, sizeof(pThis->_Data));
                return pThis;
            }
            inline void Remove() noexcept {
                RBTREE* toRemove = this;
                RBTREE* x;
                RBTREE* pRbTree;
                auto originalRed = toRemove->_Red;

                BUG_CHECK((_Parent == this || _Left == this || _Right == this || _IsNil), "Wrong NODE\n");
                if (this->_Left->_IsNil) {
                    x = this->_Right;
                    pRbTree = this->_Left;
                    pRbTree->OnRemoveNode(this);
                    pRbTree->Transplant(this, this->_Right);
                }
                else if (this->_Right->_IsNil) {
                    x = this->_Left;
                    pRbTree = this->_Right;
                    pRbTree->OnRemoveNode(this);
                    pRbTree->Transplant(this, this->_Left);
                }
                else {
                    toRemove = this->_Right;
                    while (!toRemove->_Left->_IsNil) {
                        toRemove = toRemove->_Left;
                    }
                    pRbTree = toRemove->_Left;
                    pRbTree->OnRemoveNode(this);

                    originalRed = toRemove->_Red;
                    x = toRemove->_Right;
                    if (toRemove->_Parent == this) {
                        if (!x->_IsNil) {
                            x->_Parent = toRemove;
                        }
                    }
                    else {
                        pRbTree->Transplant(toRemove, toRemove->_Right);
                        toRemove->_Right = this->_Right;
                        toRemove->_Right->_Parent = toRemove;
                    }
                    pRbTree->Transplant(this, toRemove);
                    toRemove->_Left = this->_Left;
                    toRemove->_Left->_Parent = toRemove;
                    toRemove->_Red = this->_Red;
                }
                if (!originalRed) {
                    pRbTree->FixDoubleBlack(x);
                }
                this->_Parent = this->_Left = this->_Right = this;
                this->_Red = 0;
                this->_IsNil = 1;
            }
            inline T& operator*() noexcept {
                return _Data;
            }
            inline T* operator->() noexcept {
                return &_Data;
            }
        private:
            friend class RBTREE;
            T _Data;
        };
        class ITER
        {
        public:
            inline NODE* operator*() noexcept {
                return DataPtr();
            }
            inline NODE& operator->() noexcept {
                return *DataPtr();
            }
            inline bool operator==(const ITER& Other) noexcept {
                return _Cur == Other._Cur;
            }
            inline bool operator!=(const ITER& Other) noexcept {
                return !(*this == Other);
            }
            inline ITER& operator++() noexcept {
                _Cur = _NextCur;
                UpdateCache();
                return *this;
            }
            inline ITER& operator--() noexcept {
                _Cur = _LastCur;
                UpdateCache();
                return *this;
            }
            inline NODE* DataPtr() noexcept {
                return reinterpret_cast<NODE*>(_Cur);
            }
        private:
            friend class RBTREE;
            RBTREE* _Cur;
            //防止迭代过程中删除，缓存前后节点
            RBTREE* _NextCur, * _LastCur;
            inline ITER(RBTREE* Cur) noexcept :_Cur(Cur) {
                UpdateCache();
            };
            inline void UpdateCache() noexcept {
                _NextCur = _Cur->Next();
                _LastCur = _Cur->Last();
            }
        };
        inline RBTREE() noexcept = default;
        inline RBTREE(const RBTREE& Other) noexcept = delete;
        static inline RBTREE* ForBuffer(void* Buffer) noexcept {
            RBTREE* pThis = (RBTREE*)Buffer;
            if (!pThis) {
                return nullptr;
            }
            pThis->_Parent = pThis->_Left = pThis->_Right = pThis;
            pThis->_Red = 0;
            pThis->_IsNil = 1;
            return pThis;
        }
        inline bool Empty() const noexcept {
            return _Parent == this;
        }
        inline void Insert(NODE* pNode) noexcept {
            BUG_CHECK((pNode->_Parent != pNode || pNode->_Left != pNode || pNode->_Right != pNode || !pNode->_IsNil), "Wrong NODE\n");
            pNode->_Parent = pNode->_Left = pNode->_Right = this;
            pNode->_Red = 1;
            pNode->_IsNil = 0;
            RBTREE* pTmpNode = this->_Parent;
            RBTREE* Parent = this;
            while (pTmpNode != this) {
                Parent = pTmpNode;
                int Compare;
                if constexpr (HASEQUAL<T>::Check()) {
                    if (pNode->_Data < ((NODE*)pTmpNode)->_Data)Compare = -1;
                    else if (pNode->_Data > ((NODE*)pTmpNode)->_Data)Compare = 1;
                    else Compare = 0;
                }
                else {
                    if (pNode < (NODE*)pTmpNode)Compare = -1;
                    else if (pNode > (NODE*)pTmpNode)Compare = 1;
                    else Compare = 0;
                }
                if (Compare < 0) {
                    pTmpNode = pTmpNode->_Left;
                }
                else if (Compare > 0) {
                    pTmpNode = pTmpNode->_Right;
                }
                else {
                    ((NODE*)pTmpNode)->_Data = pNode->_Data;
                    return;
                }
            }
            if (Parent == this) {
                this->_Parent = pNode;
            }
            else
            {
                int Compare;
                if constexpr (HASEQUAL<T>::Check()) {
                    Compare = pNode->_Data.Compare(((NODE*)Parent)->_Data);
                }
                else {
                    if (pNode < (NODE*)Parent)Compare = -1;
                    else if (pNode > (NODE*)Parent)Compare = 1;
                    else Compare = 0;
                }
                if (Compare < 0) {
                    Parent->_Left = pNode;
                    pNode->_Parent = Parent;
                }
                else {
                    Parent->_Right = pNode;
                    pNode->_Parent = Parent;
                }
            }
            FixViolation(pNode);
            //更新_Left与_Right
            if (_Left->_IsNil) {
                _Left = pNode;
            }
            else if (!_Left->_Left->_IsNil) {
                _Left = _Left->_Left;
            }
            if (_Right->_IsNil) {
                _Right = pNode;
            }
            else if (!_Right->_Right->_IsNil) {
                _Right = _Right->_Right;
            }
        }
        template<typename K>
        inline NODE* Find(K Key) const noexcept {
            NODE* Result = (NODE*)_Parent;
            while (!Result->_IsNil) {
                if (Result->_Data > Key) {
                    Result = (NODE*)Result->_Left;
                }
                else if (Result->_Data < Key) {
                    Result = (NODE*)Result->_Right;
                }
                else {
                    break;
                }
            }
            if (Result->_IsNil) {
                Result = nullptr;
            }
            return Result;
        }
        inline RBTREE& operator<<(NODE* pNode) noexcept {
            Insert(pNode); return *this;
        }
        inline ITER begin() noexcept {
            return ITER(_Left);
        }
        inline ITER end() noexcept {
            return ITER(this);
        }
        inline ITER rbegin() noexcept {
            return ITER(_Right);
        }
        inline ITER rend() noexcept {
            return ITER(this);
        }
    protected:
        RBTREE* _Parent = this;
        RBTREE* _Left = this;
        RBTREE* _Right = this;
        unsigned char _Red = 0;
        unsigned char _IsNil = 1;
    private:
        unsigned char _Reserve[sizeof(RBTREE*) - 1] = { 0 };
        inline RBTREE* Next() noexcept {
            //获取后一个节点
            RBTREE* Result = this;
            if (!Result->_Right->_IsNil) {
                //如果有右节点，访问右节点
                Result = Result->_Right;
                while (!Result->_Left->_IsNil)
                    Result = Result->_Left;
            }
            else {
                while (!Result->_IsNil) {
                    RBTREE* Tmp = Result;
                    Result = Result->_Parent;
                    if (Tmp == Result->_Left)
                        break;
                }
            }
            return Result;
        }
        inline RBTREE* Last() noexcept {
            //获取前一个节点
            RBTREE* Result = this;
            if (!Result->_Left->_IsNil) {
                //如果有右节点，访问右节点
                Result = Result->_Left;
                while (!Result->_Right->_IsNil)
                    Result = Result->_Right;
            }
            else {
                while (!Result->_IsNil) {
                    RBTREE* Tmp = Result;
                    Result = Result->_Parent;
                    if (Tmp == Result->_Right)
                        break;
                }
            }
            return Result;
        }
        inline void OnRemoveNode(RBTREE* pNode) noexcept {
            //正在删除指定节点
            if (_Left == pNode) {
                _Left = _Left->Next();
            }
            if (_Right == pNode) {
                _Right = _Right->Last();
            }
        }
        inline void RotateLeft(RBTREE* pNode) noexcept {
            // 左旋操作
            RBTREE* rightChild = pNode->_Right;
            pNode->_Right = rightChild->_Left;
            if (rightChild->_Left != this) {
                rightChild->_Left->_Parent = pNode;
            }
            rightChild->_Parent = pNode->_Parent;
            if (pNode->_Parent == this) {
                this->_Parent = rightChild;
            }
            else if (pNode == pNode->_Parent->_Left) {
                pNode->_Parent->_Left = rightChild;
            }
            else {
                pNode->_Parent->_Right = rightChild;
            }
            rightChild->_Left = pNode;
            pNode->_Parent = rightChild;
        }
        inline void RotateRight(RBTREE* pNode) noexcept {
            // 右旋操作
            RBTREE* leftChild = pNode->_Left;
            pNode->_Left = leftChild->_Right;
            if (leftChild->_Right != this) {
                leftChild->_Right->_Parent = pNode;
            }
            leftChild->_Parent = pNode->_Parent;
            if (pNode->_Parent == this) {
                this->_Parent = leftChild;
            }
            else if (pNode == pNode->_Parent->_Right) {
                pNode->_Parent->_Right = leftChild;
            }
            else {
                pNode->_Parent->_Left = leftChild;
            }
            leftChild->_Right = pNode;
            pNode->_Parent = leftChild;
        }
        inline void FixViolation(RBTREE* pNode) noexcept {
            // 检查并修正违反红黑树规则的情况
            RBTREE* Parent = this;
            RBTREE* GrandParent = this;
            while (pNode != this && pNode->_Red && pNode->_Parent->_Red) {
                Parent = pNode->_Parent;
                GrandParent = pNode->_Parent->_Parent;

                if (Parent == GrandParent->_Left) {
                    RBTREE* uncle = GrandParent->_Right;

                    if (uncle != this && uncle->_Red) {
                        GrandParent->_Red = 1;
                        Parent->_Red = 0;
                        uncle->_Red = 0;
                        pNode = GrandParent;
                    }
                    else {
                        if (pNode == Parent->_Right) {
                            RotateLeft(Parent);
                            pNode = Parent;
                            Parent = pNode->_Parent;
                        }
                        RotateRight(GrandParent);
                        unsigned char tRed = Parent->_Red;
                        Parent->_Red = GrandParent->_Red;
                        GrandParent->_Red = tRed;
                        pNode = Parent;
                    }
                }
                else {
                    RBTREE* uncle = GrandParent->_Left;

                    if (uncle != this && uncle->_Red) {
                        GrandParent->_Red = 1;
                        Parent->_Red = 0;
                        uncle->_Red = 0;
                        pNode = GrandParent;
                    }
                    else {
                        if (pNode == Parent->_Left) {
                            RotateRight(Parent);
                            pNode = Parent;
                            Parent = pNode->_Parent;
                        }
                        RotateLeft(GrandParent);
                        unsigned char tRed = Parent->_Red;
                        Parent->_Red = GrandParent->_Red;
                        GrandParent->_Red = tRed;
                        pNode = Parent;
                    }
                }
            }
            this->_Parent->_Red = 0;
        }
        inline void Transplant(RBTREE* u, RBTREE* v) noexcept {
            if (u->_Parent == this) {
                this->_Parent = v;
            }
            else if (u == u->_Parent->_Left) {
                u->_Parent->_Left = v;
            }
            else {
                u->_Parent->_Right = v;
            }
            if (v != this) {
                v->_Parent = u->_Parent;
            }
        }
        inline void FixDoubleBlack(RBTREE* pNode) noexcept {
            while (pNode != this->_Parent && (pNode == this || !pNode->_Red)) {
                if (pNode == pNode->_Parent->_Left) {
                    RBTREE* sibling = pNode->_Parent->_Right;
                    if (sibling->_Red) {
                        sibling->_Red = 0;
                        pNode->_Parent->_Red = 1;
                        RotateLeft(pNode->_Parent);
                        sibling = pNode->_Parent->_Right;
                    }
                    if ((sibling->_Left == this || !sibling->_Left->_Red) &&
                        (sibling->_Right == this || !sibling->_Right->_Red)) {
                        sibling->_Red = 1;
                        pNode = pNode->_Parent;
                    }
                    else {
                        if (sibling->_Right == this || !sibling->_Right->_Red) {
                            if (sibling->_Left != this) {
                                sibling->_Left->_Red = 0;
                            }
                            sibling->_Red = 1;
                            RotateRight(sibling);
                            sibling = pNode->_Parent->_Right;
                        }
                        sibling->_Red = pNode->_Parent->_Red;
                        pNode->_Parent->_Red = 0;
                        if (sibling->_Right != this) {
                            sibling->_Right->_Red = 0;
                        }
                        RotateLeft(pNode->_Parent);
                        pNode = this->_Parent;
                    }
                }
                else {
                    RBTREE* sibling = pNode->_Parent->_Left;
                    if (sibling->_Red) {
                        sibling->_Red = 0;
                        pNode->_Parent->_Red = 1;
                        RotateRight(pNode->_Parent);
                        sibling = pNode->_Parent->_Left;
                    }
                    if ((sibling->_Right == this || !sibling->_Right->_Red) &&
                        (sibling->_Left == this || !sibling->_Left->_Red)) {
                        sibling->_Red = 1;
                        pNode = pNode->_Parent;
                    }
                    else {
                        if (sibling->_Left == this || !sibling->_Left->_Red) {
                            if (sibling->_Right != this) {
                                sibling->_Right->_Red = 0;
                            }
                            sibling->_Red = 1;
                            RotateLeft(sibling);
                            sibling = pNode->_Parent->_Left;
                        }
                        sibling->_Red = pNode->_Parent->_Red;
                        pNode->_Parent->_Red = 0;
                        if (sibling->_Left != this) {
                            sibling->_Left->_Red = 0;
                        }
                        RotateRight(pNode->_Parent);
                        pNode = this->_Parent;
                    }
                }
            }
            if (pNode != this) {
                pNode->_Red = 0;
            }
        }
    };
};