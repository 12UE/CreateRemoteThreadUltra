# CreateRemoteThreadUltra
CreateRemoteThread: how to pass multiple parameters to the remote thread function without shellcode.

```c++
HANDLE WINAPI CreateRemoteThread(
  _In_   HANDLE hProcess,
  _In_   LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_   SIZE_T dwStackSize,
  _In_   LPTHREAD_START_ROUTINE lpStartAddress,
  _In_   LPVOID lpParameter,
  _In_   DWORD dwCreationFlags,
  _Out_  LPDWORD lpThreadId
);
```

# The Function
  According to the MSDN documentation, the `CreateRemoteThread` API from `kernel32.dll` allows the creation of a thread within the virtual address space of another process. This API is commonly used for process or shellcode injection purposes, with standard DLL injection being one of the most prevalent techniques. By using `CreateRemoteThread`, it is possible to "force" a remote process to load an arbitrary DLL by creating a new thread within it. The address of the `LoadLibrary` function is passed to the API as the fourth parameter (`lpStartAddress`), while a pointer to the string representing the DLL to be loaded is passed as the fifth parameter (`lpParameter`).

However, a challenge arises when the remote function expects multiple parameters. Standard DLL injection works because the `LoadLibrary` function only requires one parameter. But what if the remote function, such as `MessageBox`, expects multiple parameters? For example, `MessageBox` typically requires four parameters.

The motivation for creating this repository is to address the claim made by some individuals on the internet that passing more than one argument to a remote function is impossible. The repository aims to provide a solution for passing multiple parameters to a remote function without resorting to shellcode.

For more detailed information and code examples related to this topic, you can refer to the following repository:

# References
[CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus).
