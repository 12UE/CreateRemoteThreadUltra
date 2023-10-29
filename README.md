# Create Remote Thread Ultra
CreateRemoteThread: how to pass multiple parameters to the remote thread function without shellcode. support x86 and x64.

CreateRemoteThread：如何在没有shell代码的情况下将多个参数传递给远程线程函数。支持x86和x64。
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

For more detailed information and code examples related to this topic, you can refer to the following repository:[CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus).

	根据MSDN文档，“kernel32.dll”中的“CreateRemoteThread”API允许在另一个进程的虚拟地址空间中创建线程。此API通常用于进程或外壳代码注入，标准DLL注入是最流行的技术之一。通过使用“CreateRemoteThread”，可以通过在远程进程中创建新线程来“强制”远程进程加载任意DLL。“LoadLibrary”函数的地址作为第四个参数（“lpStartAddress”）传递给API，而指向表示要加载的DLL的字符串的指针作为第五个参数（‘lpParameter’）传递。


然而，当远程功能需要多个参数时，就会出现挑战。标准DLL注入之所以有效，是因为“LoadLibrary”函数只需要一个参数。但是，如果远程函数（如“MessageBox”）需要多个参数，该怎么办？例如，“MessageBox”通常需要四个参数。


创建这个存储库的动机是为了解决一些人在互联网上提出的不可能将多个参数传递给远程函数的说法。该存储库旨在提供一种解决方案，将多个参数传递给远程函数，而无需使用外壳代码。


有关此主题的更多详细信息和代码示例，您可以参考以下存储库：[CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus).

# The Problem
When using the `CreateRemoteThread` function from `kernel32.dll` to create a remote thread, typically only one parameter can be passed to the remote thread function. This is because the fifth parameter `lpParameter` of the `CreateRemoteThread` function accepts only a single `LPVOID` parameter, which is a pointer to arbitrary data.

However, there are situations where we need to pass multiple parameters to the remote thread function. For example, if the remote thread function is `MessageBox`, which expects four parameters: the window handle, the message text, the window title, and the message box type. In such cases, we need to find a way to pass multiple parameters to the remote thread function.

One common solution is to create a custom data structure to encapsulate the multiple parameters and pass a pointer to that structure as the `lpParameter` parameter to the `CreateRemoteThread` function. In the remote thread function, we can then dereference that pointer to access the multiple parameters.

In this example, we define a `ThreadParams` structure that contains the four parameters expected by the `MessageBox` function. Then, in the remote thread function `RemoteThreadProc`, we cast the `lpParam` parameter to type `ThreadParams*` and access the passed multiple parameters through that pointer. Finally, we free the memory allocated for the parameter structure.

Using this approach, we can pass multiple parameters to a remote thread function through the `CreateRemoteThread` function and perform the desired operations in the remote thread. This method overcomes the limitation of passing only one parameter and allows us to use multiple parameters in the remote thread function.
使用“kernel32.dll”中的“CreateRemoteThread”函数创建远程线程时，通常只能向远程线程函数传递一个参数。这是因为“CreateRemoteThread”函数的第五个参数“lpParameter”只接受一个“LPVOID”参数，该参数是指向任意数据的指针。


但是，在某些情况下，我们需要将多个参数传递给远程线程函数。例如，如果远程线程函数是“MessageBox”，它需要四个参数：窗口句柄、消息文本、窗口标题和消息框类型。在这种情况下，我们需要找到一种方法，将多个参数传递给远程线程函数。


一种常见的解决方案是创建一个自定义数据结构来封装多个参数，并将指向该结构的指针作为“lpParameter”参数传递给“CreateRemoteThread”函数。在远程线程函数中，我们可以取消引用该指针来访问多个参数。


在本例中，我们定义了一个“ThreadParams”结构，该结构包含“MessageBox”函数所需的四个参数。然后，在远程线程函数“RemoteThreadProc”中，我们将“lpParam”参数强制转换为“ThreadParams*”类型，并通过该指针访问传递的多个参数。最后，我们释放为参数结构分配的内存。


使用这种方法，我们可以通过“CreateRemoteThread”函数将多个参数传递给远程线程函数，并在远程线程中执行所需的操作。这种方法克服了只传递一个参数的限制，并允许我们在远程线程函数中使用多个参数。
# References/引用
[CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus).
