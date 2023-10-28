
#include <iostream>
#include <Windows.h>
#include <Zydis/Zydis.h>
#include <TlHelp32.h>
#pragma comment(lib,"Zydis.lib")
#include <atomic>
#include <algorithm>
#include <mutex>
#include <vector>
#if defined _WIN64
using UDWORD = DWORD64;
#define XIP Rip
#define XAX Rax
constexpr auto USERADDR_MAX = 0x7fffffff0000;
#define U64_ "%llx"  //U64_使用的时候注意不要多加"%" 号了
#else
using UDWORD = DWORD32;
#define XIP Eip
#define XAX Eax
#define U64_ "%x"//U64_使用的时候注意不要多加"%" 号了
constexpr auto USERADDR_MAX = 0xBFFE'FFFF;
#endif
UDWORD GetLength(BYTE* _buffer, UDWORD _length = 65535) {
    ZyanU64 runtime_address = (ZyanU64)_buffer;
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction{};
    int length = 0;
#ifdef _WIN64
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, runtime_address, _buffer + offset, _length - offset, &instruction))) {
#else
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, runtime_address, _buffer + offset, _length - offset, &instruction))) {
#endif // !_WIN64
        offset += instruction.info.length;
        runtime_address += instruction.info.length;
        length += instruction.info.length;
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET)
            break;
    }
    return length;
}
template<typename T>struct remove_const_pointer { using type = typename std::remove_pointer<std::remove_const_t<T>>::type; };
template<typename T> using remove_const_pointer_t = typename remove_const_pointer<T>::type;
template<class Tx, class Ty> inline size_t _ucsicmp(const Tx* str1, const Ty* str2) {//匹配字符串
    if (!str1 || !str2) throw std::exception("str1 or str2 is nullptr");
    std::wstring wstr1{}, wstr2{};
    std::string  strtemp{};
    if constexpr (!std::is_same_v<remove_const_pointer_t<Tx>, wchar_t>) {
        strtemp = str1;
        wstr1 = std::wstring(strtemp.begin(), strtemp.end());
    }
    else {
        wstr1 = str1;
    }
    if constexpr (!std::is_same_v<remove_const_pointer_t<Ty>, wchar_t>) {
        strtemp = str2;
        wstr2 = std::wstring(strtemp.begin(), strtemp.end());
    }
    else {
        wstr2 = str2;
    }
    std::transform(wstr1.begin(), wstr1.end(), wstr1.begin(), towlower);
    std::transform(wstr2.begin(), wstr2.end(), wstr2.begin(), towlower);
    return wstr1.compare(wstr2);
}
#define DELETE_COPYMOVE_CONSTRUCTOR(TYPE) TYPE(const TYPE&)=delete;TYPE(TYPE&&) = delete;void operator= (const TYPE&) = delete;void operator= (TYPE&&) = delete;
template<typename T >
class SingleTon {
private:
    DELETE_COPYMOVE_CONSTRUCTOR(SingleTon)
public:
    SingleTon() = default;
    template <class... Args>
    static T& GetInstance(Args&& ...args) {
        static std::once_flag flag{};
        static std::shared_ptr<T> instance = nullptr;
        if (!instance) {
            std::call_once(flag, [&]() {
                instance = std::make_shared<T>(args...);
            });
        }
        return *instance.get();
    }
};
template <class... Args>
struct ThreadData {
    std::tuple<Args...> datas;
};
template <class...Args, size_t... Indices>
__forceinline decltype(auto) ThreadFunctionImpl(ThreadData<Args...>* threadData, std::index_sequence<Indices...>) noexcept {
    using RetType = decltype(std::get<0>(threadData->datas)(std::get<Indices + 1>(threadData->datas)...));
    if (threadData) return std::get<0>(threadData->datas)(std::get<Indices + 1>(threadData->datas)...);
    return RetType();
}
template <class... Args>
__declspec(noinline)  decltype(auto) ThreadFunction(void* param)noexcept {
    auto threadData = static_cast<ThreadData<Args...>*>(param);
    if (threadData)return ThreadFunctionImpl(threadData, std::make_index_sequence<sizeof...(Args) - 1>{});
    using RetValue = decltype(ThreadFunctionImpl(threadData, std::make_index_sequence<sizeof...(Args) - 1>{}));
    return RetValue();
}
class Shared_Ptr;
template<class T>Shared_Ptr make_Shared() { return Shared_Ptr(sizeof(T)); }
template<class T>Shared_Ptr make_Shared(size_t nsize) { return Shared_Ptr(sizeof(T) * nsize); }
class Process :public SingleTon<Process> {
    HANDLE m_hProcess;
    DWORD m_pid;
    std::atomic_bool m_bAttached;
    std::vector<Shared_Ptr> m_vecAllocMem;
    template<typename T, typename ...Args>
    void process(T& arg, Args&...args) {
        processparameter(arg);
		if constexpr (sizeof...(args)>0) process(args...);
    }
    template<typename T>void processparameter(T& arg) {}
    void processparameter(const char*& arg);
public:
    void Attach(const char* _szProcessName) {
        // 根据进程名获取进程ID
        DWORD pid = GetProcessIdByName(_szProcessName);
        if (pid != 0) {
            m_pid = pid;
            m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
            m_bAttached = true;
        }
    }
    ULONG _WriteApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) {
        if (m_bAttached) {
            SIZE_T bytesWritten = 0;
            WriteProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten);
            return bytesWritten;
        }
        return 0;
    }
    UDWORD _AllocMemApi(SIZE_T dwSize, LPVOID PageBase=NULL) {
        if (m_bAttached) {
            LPVOID allocatedMemory = VirtualAllocEx(m_hProcess, PageBase, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            return reinterpret_cast<UDWORD>(allocatedMemory);
        }
        return 0;
    }
    int _FreeMemApi(LPVOID lpAddress) {
        if (m_bAttached) {
            return VirtualFreeEx(m_hProcess, lpAddress, 0, MEM_RELEASE);
        }
        return 0;
    }
    void RemoteThreadShell(BYTE* Shell, BYTE* param, int nShellSize, int ParamnSize);
    template<class _Fn, class ...Arg>
    void RemoteThreadCall(_Fn&& _Fx, Arg...args){
        // 检查是否已经连接到远程线程，如果未连接，则抛出异常
        if(!m_bAttached)throw std::exception("m_bAttached is false");
        // 如果有参数，则调用 process() 函数处理这些参数
        if constexpr (sizeof...(args))process(args...);
        // 创建一个 ThreadData 对象，将函数对象和参数存储在其中
        ThreadData<std::decay_t<_Fn>, std::decay_t<Arg>...> threadData{};
        threadData.datas = std::tuple(std::forward<std::decay_t<_Fn>>(_Fx), std::forward<Arg>(args)...);
        // 获取 ThreadFunction 的长度
        auto pThreadFunc = &ThreadFunction< std::decay_t<_Fn>, std::decay_t<Arg>...>;
        int length = GetLength((BYTE*)pThreadFunc);
        // 在远程线程中调用 RemoteThreadShell 函数，将 ThreadFunction 和 threadData 作为参数传递
        RemoteThreadShell((BYTE*)pThreadFunc, (BYTE*)&threadData, length, sizeof(threadData));
        // 创建一个 ThreadData 对象，将函数对象和参数存储在其中
        if (!m_vecAllocMem.empty()) {
            for (auto& ptr : m_vecAllocMem) ptr.Release();
            m_vecAllocMem.clear();
        }
    }
private:
    DWORD GetProcessIdByName(const char* processName) {
        DWORD pid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 processEntry = { 0 };
            processEntry.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &processEntry)) {
                do {
                    if (_ucsicmp(processEntry.szExeFile, processName) == 0) {
                        pid = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &processEntry));
            }
            CloseHandle(hSnapshot);
        }
        return pid;
    }
};
class Shared_Ptr {
    LPVOID BaseAddress = nullptr;
    int refCount = 0;
    void AddRef() {
        refCount++;
    }
public:
    Shared_Ptr(void* Addr) {
        BaseAddress = Addr;
        AddRef();
    }
    template<class T>
    Shared_Ptr() {
        AddRef();
        BaseAddress = (LPVOID)Process::GetInstance()._AllocMemApi(sizeof(T));
    }
    Shared_Ptr(size_t nsize) {
        AddRef();
        BaseAddress = (LPVOID)Process::GetInstance()._AllocMemApi(nsize);
    }
    Shared_Ptr(const Shared_Ptr& other) : BaseAddress(other.BaseAddress), refCount(other.refCount) {
        AddRef();
    }
    Shared_Ptr& operator=(const Shared_Ptr& other) {
        if (this != &other) {
            Release();
            BaseAddress = other.BaseAddress;
            refCount = other.refCount;
            AddRef();
        }
        return *this;
    }
    LPVOID get() {
        AddRef();
        return BaseAddress;
    }
    LPVOID raw() {
        return BaseAddress;
    }
    UDWORD getUDWORD() {
        AddRef();
        return (UDWORD)BaseAddress;
    }
    ~Shared_Ptr() {
        Release();
    }
    void Release() {
        refCount--;
        if (BaseAddress && refCount <= 0) Process::GetInstance()._FreeMemApi(BaseAddress);
    }
    operator bool() { return BaseAddress != nullptr; }
};
int main()
{
    auto & Process = Process::GetInstance();
    Process.Attach("notepad.exe");
    Process.RemoteThreadCall(MessageBoxA, nullptr, "Hello World", "Hello World", 0);

}
void Process::processparameter(const char*& arg)
{
    int nlen = strlen(arg) + 1;
    auto p = make_Shared<char>(nlen * sizeof(char));
    if (p) {
        m_vecAllocMem.push_back(p);
        _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(char));
        arg = (const char*)p.raw();
    }
}

void Process::RemoteThreadShell(BYTE* Shell, BYTE* param, int nShellSize, int ParamnSize){
    if (m_bAttached) {
        if (!Shell || nShellSize == 0)throw std::exception("Shell is nullptr");
        if (!param || ParamnSize == 0)throw std::exception("param is nullptr");
        auto pThreadFunc = make_Shared<BYTE>(nShellSize);
        auto pThreadParam = make_Shared<BYTE>(ParamnSize);
        if (!pThreadFunc || !pThreadParam)throw std::exception("make_Shared is nullptr");
        _WriteApi(pThreadFunc.get(), Shell, nShellSize);
        _WriteApi(pThreadParam.get(), param, ParamnSize);
        HANDLE hThread = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadFunc.get(), pThreadParam.get(), 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }
}
