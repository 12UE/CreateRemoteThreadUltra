#include <iostream>
#include <Windows.h>
#include <Zydis/Zydis.h>//through vcpkg install Zydis:x64-windows:vcpkg.exe install Zydis:x64-windows-static
#include <TlHelp32.h>
#pragma comment(lib,"Zydis.lib")
#include <atomic>
#include <algorithm>
#include <mutex>
#include <vector>
#include <tuple>
#if defined _WIN64
using UDWORD = DWORD64;
#define XIP Rip//instruction pointer
#define XAX Rax//accumulator
#define U64_ "%llx"  //U64_ When using, be careful not to add "%" again
#else
using UDWORD = DWORD32;
#define XIP Eip//instruction pointer
#define XAX Eax//accumulator
#define U64_ "%x"//U64_ When using, be careful not to add "%" again
#endif
UDWORD GetLength(BYTE* _buffer, UDWORD _length = 65535) {//Get the length of the function default 65535 because the function is not so long
    ZyanU64 runtime_address = (ZyanU64)_buffer;
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction{};
    int length = 0;
#ifdef _WIN64
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, runtime_address, _buffer + offset, _length - offset, &instruction))) {//disassemble
#else
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, runtime_address, _buffer + offset, _length - offset, &instruction))) {//disassemble
#endif // !_WIN64
        offset += instruction.info.length;
        runtime_address += instruction.info.length;//add instruction length
        length += instruction.info.length;//add instruction length
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET) break;
    }
    return length;
}
template<typename T>struct remove_const_pointer { using type = typename std::remove_pointer<std::remove_const_t<T>>::type; };//remove const pointer
template<typename T> using remove_const_pointer_t = typename remove_const_pointer<T>::type;//remove const pointer
template<class Tx, class Ty> inline size_t _ucsicmp(const Tx* str1, const Ty* str2) {//ignore case compare ignore type wchar_t wstring or char string
    if (!str1 || !str2) throw std::exception("str1 or str2 is nullptr");
    std::wstring wstr1{}, wstr2{};
    std::string  strtemp{};
    if constexpr (!std::is_same_v<remove_const_pointer_t<Tx>, wchar_t>) {
        strtemp = str1;
        wstr1 = std::wstring(strtemp.begin(), strtemp.end());//transform to wstring
    }else {
        wstr1 = str1;
    }
    if constexpr (!std::is_same_v<remove_const_pointer_t<Ty>, wchar_t>) {
        strtemp = str2;
        wstr2 = std::wstring(strtemp.begin(), strtemp.end());//transform to wstring
    }else {
        wstr2 = str2;
    }
    std::transform(wstr1.begin(), wstr1.end(), wstr1.begin(), towlower);//transform to lower
    std::transform(wstr2.begin(), wstr2.end(), wstr2.begin(), towlower);//transform to lower
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
    static T& GetInstance(Args&& ...args) {//get instance this function is thread safe and support parameter
        static std::once_flag flag{};
        static std::shared_ptr<T> instance = nullptr;
        if (!instance) {
            std::call_once(flag, [&]() {//call once
                instance = std::make_shared<T>(args...);//element constructor through parameters
            });
        }
        return *instance.get();//return instance
    }
};
template <class... Args>
struct ThreadData {//Thread Data Struct
    std::tuple<Args...> datas;
};
template <class...Args, size_t... Indices>
__forceinline decltype(auto) ThreadFunctionImpl(ThreadData<Args...>* threadData, std::index_sequence<Indices...>) noexcept {//thread function impliment
    using RetType = decltype(std::get<0>(threadData->datas)(std::get<Indices + 1>(threadData->datas)...));//get return type
    if (threadData) return std::get<0>(threadData->datas)(std::get<Indices + 1>(threadData->datas)...);//if threadData is not nullptr call function
    return RetType();//return RetType
}
template <class... Args>
__declspec(noinline)  decltype(auto) ThreadFunction(void* param)noexcept {//thread function
    auto threadData = static_cast<ThreadData<Args...>*>(param);
    if (threadData)return ThreadFunctionImpl(threadData, std::make_index_sequence<sizeof...(Args) - 1>{});//if threadData is not nullptr call ThreadFunctionImpl
    using RetValue = decltype(ThreadFunctionImpl(threadData, std::make_index_sequence<sizeof...(Args) - 1>{}));//get return type
    return RetValue();//return RetValue
}
class Shared_Ptr;
template<class T>Shared_Ptr make_Shared() { return Shared_Ptr(sizeof(T)); }//to make Shared_Ptr
template<class T>Shared_Ptr make_Shared(size_t nsize) { return Shared_Ptr(sizeof(T) * nsize); }//to make Shared_Ptr
class Process :public SingleTon<Process> {//Singleton
    HANDLE m_hProcess=INVALID_HANDLE_VALUE;
    DWORD m_pid;//process id
    std::atomic_bool m_bAttached;//atomic bool
    std::vector<Shared_Ptr> m_vecAllocMem;//vector for allocated memory
    template<typename T, typename ...Args>
    void process(T& arg, Args&...args) {//partially specialized template
        processparameter(arg);
		if constexpr (sizeof...(args)>0) process(args...);
    }
    template<typename T>void processparameter(T& arg) {}
    void processparameter(const char*& arg);//process const char* parameter
    void processparameter(const wchar_t*& arg);//process const wchar_t* parameter
public:
    void Attach(const char* _szProcessName) {//attach process
        //get process id
        auto pid = GetProcessIdByName(_szProcessName);
        if (pid != 0) {
            m_pid = pid;
            m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
            m_bAttached = true;
        }
    }
    ULONG _WriteApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) {//WriteProcessMemory
        if (m_bAttached) {
            SIZE_T bytesWritten = 0;
            WriteProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten);
            return bytesWritten;
        }
        return 0;
    }
    UDWORD _AllocMemApi(SIZE_T dwSize, LPVOID PageBase=NULL) {//return allocated memory address
        if (m_bAttached) {
            auto allocatedMemory = VirtualAllocEx(m_hProcess, PageBase, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            return reinterpret_cast<UDWORD>(allocatedMemory);
        }
        return 0;
    }
    int _FreeMemApi(LPVOID lpAddress) {//free memory
        if (m_bAttached)return VirtualFreeEx(m_hProcess, lpAddress, 0, MEM_RELEASE);
        return 0;
    }
    void RemoteThreadShell(BYTE* Shell, BYTE* param, int nShellSize, int ParamnSize);//Create Remote Thread and execute Shell
    template<class _Fn, class ...Arg>
    void RemoteThreadCall(_Fn&& _Fx, Arg...args){
        // Check if the process is attached
        if(!m_bAttached)throw std::exception("m_bAttached is false");
        // if args is not empty, process it
        if constexpr (sizeof...(args))process(args...);
        // Create a ThreadData object，store the function object and parameters in it
        ThreadData<std::decay_t<_Fn>, std::decay_t<Arg>...> threadData{};
        threadData.datas = std::tuple<std::decay_t<_Fn>, std::decay_t<Arg>...>(std::forward<std::decay_t<_Fn>>(_Fx), std::forward<Arg>(args)...);
        // Get ThreadFunction Length
        auto pThreadFunc = &ThreadFunction< std::decay_t<_Fn>, std::decay_t<Arg>...>;
        int length = (int)GetLength((BYTE*)pThreadFunc);
        // Call RemoteThreadShell
        RemoteThreadShell((BYTE*)pThreadFunc, (BYTE*)&threadData, length, sizeof(threadData));
        // Clear the memory allocated by the processparameter function
        if (!m_vecAllocMem.empty()) {
            for (auto& ptr : m_vecAllocMem) ptr.Release();//release memory
            m_vecAllocMem.clear();//clear vector each time
        }
    }
private:
    DWORD GetProcessIdByName(const char* processName) {//get process id by name
        DWORD pid = 0;
        auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
//Shared_Ptr when the refCount is 0, the memory will be released deconstructor will call Release function
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
    Shared_Ptr& operator=(const Shared_Ptr& other) {//copy assignment
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
    void Release() {//release and refCount--
        refCount--;
        if (BaseAddress && refCount <= 0) Process::GetInstance()._FreeMemApi(BaseAddress);
    }
    operator bool() { return BaseAddress != nullptr; }
};
int main()
{
    auto & Process = Process::GetInstance();//get instance
    Process.Attach("notepad.exe");//attach process
    Process.RemoteThreadCall(MessageBoxA, nullptr, "Hello World", "Hello World", 0);//call MessageBoxA

}
void Process::processparameter(const char*& arg){//process parameter
    auto nlen = (int)strlen(arg) + 1;
    auto p = make_Shared<char>(nlen * sizeof(char));
    if (p) {
        m_vecAllocMem.push_back(p);
        _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(char));
        arg = (const char*)p.raw();
    }
}
void Process::processparameter(const wchar_t*& arg){//process parameter
    auto nlen = (int)wcslen(arg) + 1;
    auto p = make_Shared<wchar_t>(nlen * sizeof(wchar_t));
    if (p) {
        m_vecAllocMem.push_back(p);
        _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(wchar_t));
        arg = (const wchar_t*)p.raw();
    }
}
void Process::RemoteThreadShell(BYTE* Shell, BYTE* param, int nShellSize, int ParamnSize){
    if (m_bAttached) {
        if (!Shell || nShellSize == 0)throw std::exception("Shell is nullptr");
        if (!param || ParamnSize == 0)throw std::exception("param is nullptr");
        auto pThreadFunc = make_Shared<BYTE>(nShellSize);//allocate memory
        auto pThreadParam = make_Shared<BYTE>(ParamnSize);//allocate memory
        if (!pThreadFunc || !pThreadParam)throw std::exception("make_Shared is nullptr");
        _WriteApi(pThreadFunc.get(), Shell, nShellSize);//write shell
        _WriteApi(pThreadParam.get(), param, ParamnSize); //write param
        auto hThread = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadFunc.get(), pThreadParam.get(), 0, NULL);//create remote thread
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);//wait thread exit
            CloseHandle(hThread);
        }
    }
}
