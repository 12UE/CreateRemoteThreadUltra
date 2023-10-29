# Create Remote Thread Ultra
`CreateRemoteThread`: How to pass multiple parameters to a remote thread function without using Shellcode. Supports x86 and x64 relaese Support LLVM.

`CreateRemoteThread` is an API located in `kernel32.dll` that allows creating threads within the virtual address space of another process. This API is commonly used for process or Shellcode injection purposes, where standard DLL injection is one of the most common techniques. By using `CreateRemoteThread`, an arbitrary DLL can be "forced" into the target process by creating a new thread within it. The fourth parameter of the API, `lpStartAddress`, requires passing the address of the LoadLibrary function, while the fifth parameter, `lpParameter`, requires passing a pointer to the string representing the DLL to be loaded.

However, a challenge arises when the remote function requires multiple parameters. Standard DLL injection works effectively because the `LoadLibrary` function only requires one parameter. But what if the remote function, such as `MessageBox`, requires multiple parameters? For example, MessageBox typically requires four parameters.

The motivation behind creating this repository is to address the notion found on the internet that multiple parameters cannot be passed to a remote function without using Shellcode. 

The goal of this repository is to provide a solution for passing multiple parameters to a remote function without the need for Shellcode.

If you're interested in this topic and would like to delve into more detailed information and related code examples, please refer to the following repository: [CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus).

# Issue
When creating a remote thread using the `CreateRemoteThread` function from `kernel32.dll`, typically only one parameter can be passed to the remote thread function. 

This is because the fifth parameter, `lpParameter`, of the `CreateRemoteThread` function only accepts an `LPVOID` type parameter, which is a pointer to arbitrary data.

However, in certain cases, there is a need to pass multiple parameters to the remote thread function. For instance, if the remote thread function is MessageBox, it requires four parameters: window handle, message text, window title, and message box type. In such situations, we need to find a way to pass multiple parameters to the remote thread function.

One common solution is to create a custom data structure that encapsulates the multiple parameters and pass a pointer to this structure as the lpParameter parameter to the `CreateRemoteThread` function. In the remote thread function, we can dereference this pointer to access the passed multiple parameters.

In this example, we define a ThreadParams structure that contains the four parameters required by the `MessageBox` function. Then, in the remote thread function RemoteThreadProc, we forcefully cast the lpParam parameter to the ThreadParams* type and access the passed multiple parameters through that pointer. Finally, we release the memory allocated for the parameter structure.

By using this approach, we can pass multiple parameters to the remote thread function through the CreateRemoteThread function and perform the desired operations within the remote thread. This method overcomes the limitation of passing only one parameter and allows us to use multiple parameters in the remote thread function.

# References
[CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus)
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
# Create Remote Thread Ultra
`CreateRemoteThread`: 如何在没有 Shellcode 的情况下将多个参数传递给远程线程函数。支持 x86 和 x64-Realease 支持LLVM。

`CreateRemoteThread` 是一个 API，位于 `kernel32.dll` 中，允许在另一个进程的虚拟地址空间中创建线程。

这个 API 通常用于进程或 Shellcode 注入的目的，其中标准的 DLL 注入是最常见的技术之一。

通过使用`CreateRemoteThread`，可以通过在目标进程中创建一个新的线程来"强制"目标进程加载任意的 DLL。

API 的第四个参数（lpStartAddress）需要传递 LoadLibrary 函数的地址，而第五个参数（lpParameter）需要传递指向要加载的 DLL 字符串的指针。

然而，当远程函数需要多个参数时，就会面临一个挑战。标准的 DLL 注入之所以有效，是因为 `LoadLibrary` 函数只需要一个参数。但是，如果远程函数（例如 `MessageBox`）需要多个参数时，应该怎么办呢？例如，`MessageBox` 通常需要四个参数。

创建这个存储库的动机是为了回应互联网上一些人的观点，即在不使用 Shellcode 的情况下，无法传递多个参数给远程函数。这个存储库的目标是提供一种解决方案，可以传递多个参数给远程函数，而不需要使用 Shellcode。
# 问题
使用 `kernel32.dll` 中的 `CreateRemoteThread` 函数创建远程线程时，通常只能向远程线程函数传递一个参数。这是因为 `CreateRemoteThread` 函数的第五个参数 `lpParameter` 只接受一个 `LPVOID` 类型的参数，即指向任意数据的指针。

然而，在某些情况下，我们需要向远程线程函数传递多个参数。例如，如果远程线程函数是 `MessageBox`，它需要四个参数：窗口句柄、消息文本、窗口标题和消息框类型。在这种情况下，我们需要找到一种方法来传递多个参数给远程线程函数。

一种常见的解决方案是创建一个自定义的数据结构，将多个参数封装在这个结构中，并将指向该结构的指针作为 `lpParameter` 参数传递给 `CreateRemoteThread` 函数。在远程线程函数中，我们可以通过对该指针进行解引用来访问传递的多个参数。

在这个例子中，我们定义了一个 ThreadParams 结构，该结构包含 `MessageBox` 函数所需的四个参数。然后，在远程线程函数 RemoteThreadProc 中，我们将 `lpParam` 参数强制转换为 ThreadParams* 类型，并通过该指针访问传递的多个参数。最后，我们释放为参数结构分配的内存。

使用这种方法，我们可以通过 `CreateRemoteThread` 函数将多个参数传递给远程线程函数，并在远程线程中执行所需的操作。这种方法克服了只能传递一个参数的限制，允许我们在远程线程函数中使用多个参数。# 参考资料
# 引用
[CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus)