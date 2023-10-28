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
#The Function
  As stated by the related MSDN page, the CreateRemoteThread API from kernel32.dll 
creates a thread that runs in the virtual address space of another process. This 
API is often used for process or shellcode injection purposes. Standard dll injection
is perhaps the most common amongst these techniques. CreateRemoteThread can 'force'
the remote process to load an arbitrary .dll by opening a new thread in it. 
The LoadLibrary address is passed to the API as LPTHREAD_START_ROUTINE (4th parameter), 
while a pointer to the string (.dll to be loaded) written in the remote process is passed as 5th parameter.
#The problem
  Standard .dll injection works because the LoadLibrary API expects one parameter only. 
But what if the remote function expects multiple parameters?
What if the function is MessageBox for instance? (MessageBox expects four parameters).
I wanted to create this repository because some people on the Internet have said 
that passing more than one argument to the remote function is impossible.
#References
https://github.com/lem0nSec/CreateRemoteThreadPlus
