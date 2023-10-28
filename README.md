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
# The Problem
When using the `CreateRemoteThread` function from `kernel32.dll` to create a remote thread, typically only one parameter can be passed to the remote thread function. This is because the fifth parameter `lpParameter` of the `CreateRemoteThread` function accepts only a single `LPVOID` parameter, which is a pointer to arbitrary data.

However, there are situations where we need to pass multiple parameters to the remote thread function. For example, if the remote thread function is `MessageBox`, which expects four parameters: the window handle, the message text, the window title, and the message box type. In such cases, we need to find a way to pass multiple parameters to the remote thread function.

One common solution is to create a custom data structure to encapsulate the multiple parameters and pass a pointer to that structure as the `lpParameter` parameter to the `CreateRemoteThread` function. In the remote thread function, we can then dereference that pointer to access the multiple parameters.

In this example, we define a `ThreadParams` structure that contains the four parameters expected by the `MessageBox` function. Then, in the remote thread function `RemoteThreadProc`, we cast the `lpParam` parameter to type `ThreadParams*` and access the passed multiple parameters through that pointer. Finally, we free the memory allocated for the parameter structure.

Using this approach, we can pass multiple parameters to a remote thread function through the `CreateRemoteThread` function and perform the desired operations in the remote thread. This method overcomes the limitation of passing only one parameter and allows us to use multiple parameters in the remote thread function.
# References
[CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus).
