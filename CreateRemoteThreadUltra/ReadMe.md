The `CreateRemoteThread` function from `kernel32.dll` allows you to create a thread in the virtual address space of another process. It is commonly used for process or shellcode injection purposes. By using this function, you can force a remote process to load an arbitrary DLL by opening a new thread within it. The address of the `LoadLibrary` function is passed as the fourth parameter (`lpStartAddress`), and a pointer to the string representing the DLL to be loaded is passed as the fifth parameter (`lpParameter`).

The problem arises when the remote function expects multiple parameters. The standard DLL injection technique works because the `LoadLibrary` function expects only one parameter. But what if the remote function, such as `MessageBox`, expects multiple parameters?

Some people on the internet have claimed that passing more than one argument to the remote function is impossible. 

However, this repository aims to address that claim and provide a solution to pass multiple parameters to the remote function without resorting to shellcode.

For more information and code examples, you can refer to the following repository: [CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus)