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
`CreateRemoteThread`: �����û�� Shellcode ������½�����������ݸ�Զ���̺߳�����֧�� x86 �� x64-Realease ֧��LLVM��

`CreateRemoteThread` ��һ�� API��λ�� `kernel32.dll` �У���������һ�����̵������ַ�ռ��д����̡߳�

��� API ͨ�����ڽ��̻� Shellcode ע���Ŀ�ģ����б�׼�� DLL ע��������ļ���֮һ��

ͨ��ʹ��`CreateRemoteThread`������ͨ����Ŀ������д���һ���µ��߳���"ǿ��"Ŀ����̼�������� DLL��

API �ĵ��ĸ�������lpStartAddress����Ҫ���� LoadLibrary �����ĵ�ַ���������������lpParameter����Ҫ����ָ��Ҫ���ص� DLL �ַ�����ָ�롣

Ȼ������Զ�̺�����Ҫ�������ʱ���ͻ�����һ����ս����׼�� DLL ע��֮������Ч������Ϊ `LoadLibrary` ����ֻ��Ҫһ�����������ǣ����Զ�̺��������� `MessageBox`����Ҫ�������ʱ��Ӧ����ô���أ����磬`MessageBox` ͨ����Ҫ�ĸ�������

��������洢��Ķ�����Ϊ�˻�Ӧ��������һЩ�˵Ĺ۵㣬���ڲ�ʹ�� Shellcode ������£��޷����ݶ��������Զ�̺���������洢���Ŀ�����ṩһ�ֽ�����������Դ��ݶ��������Զ�̺�����������Ҫʹ�� Shellcode��
# ����
ʹ�� `kernel32.dll` �е� `CreateRemoteThread` ��������Զ���߳�ʱ��ͨ��ֻ����Զ���̺߳�������һ��������������Ϊ `CreateRemoteThread` �����ĵ�������� `lpParameter` ֻ����һ�� `LPVOID` ���͵Ĳ�������ָ���������ݵ�ָ�롣

Ȼ������ĳЩ����£�������Ҫ��Զ���̺߳������ݶ�����������磬���Զ���̺߳����� `MessageBox`������Ҫ�ĸ����������ھ������Ϣ�ı������ڱ������Ϣ�����͡�����������£�������Ҫ�ҵ�һ�ַ��������ݶ��������Զ���̺߳�����

һ�ֳ����Ľ�������Ǵ���һ���Զ�������ݽṹ�������������װ������ṹ�У�����ָ��ýṹ��ָ����Ϊ `lpParameter` �������ݸ� `CreateRemoteThread` ��������Զ���̺߳����У����ǿ���ͨ���Ը�ָ����н����������ʴ��ݵĶ��������

����������У����Ƕ�����һ�� ThreadParams �ṹ���ýṹ���� `MessageBox` ����������ĸ�������Ȼ����Զ���̺߳��� RemoteThreadProc �У����ǽ� `lpParam` ����ǿ��ת��Ϊ ThreadParams* ���ͣ���ͨ����ָ����ʴ��ݵĶ����������������ͷ�Ϊ�����ṹ������ڴ档

ʹ�����ַ��������ǿ���ͨ�� `CreateRemoteThread` ����������������ݸ�Զ���̺߳���������Զ���߳���ִ������Ĳ��������ַ����˷���ֻ�ܴ���һ�����������ƣ�����������Զ���̺߳�����ʹ�ö��������# �ο�����
# ����
[CreateRemoteThreadPlus](https://github.com/lem0nSec/CreateRemoteThreadPlus)