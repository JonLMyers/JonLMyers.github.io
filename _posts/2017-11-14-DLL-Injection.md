---
layout: post
title: Introduction to Reflective DLL Injection
categories: [Security]
tags: [Windows, Red Team, Development, Privilege Esc, DLL Injection, Malware, Tools]
description: An in depth introduction to writing a reflective DLL injector from scratch
---
[overview]: ../../../../images/posts/dll_injection/image4.png
[handleapi]: ../../../../images/posts/dll_injection/image1.png
[demo]: ../../../../images/posts/dll_injection/image2.png
[writeprocessapi]: ../../../../images/posts/dll_injection/image3.png
[virtualalloc]: ../../../../images/posts/dll_injection/image5.png
[createremote]: ../../../../images/posts/dll_injection/image6.png

DLL injection serves as an incredibly useful technique for those looking to load their custom libraries into a process and unify with it as one.  This provides developers enormous amounts of power over deployed applications and with that comes a great responsibility which is often taken advantage of.   Adversaries of all different kinds may use this post exploitation technique to establish persistence by hiding their shells within critical system processes.  By hiding within these processes adversaries are able to remain undetected much longer than being exposed on the surface of the system itself.  Additionally, adversaries can bypass firewall protections by injecting their libraries into trusted processes that have the ability to travel through the firewall.  In the rest of this post I will cover some key aspects of the DLL injection technique and write a simple injector as a proof of concept.  All code for this blog can be found on my Github at: <https://github.com/JonLMyers/InjectX>
## Overview ##
<br/>
<br/>
![DLL Injection Overview][overview]
<br/>
<br/>
<br/>
The first step of injecting DLLs into an application is creating a handle to the process for later interaction.  Microsoft provides the OpenProcess function as a means to open an existing local process object.

![Handle API DOC][handleapi]
The dwDesiredAccess parameter is used to request certain access rights to the process.  There are several different options that can be set to request different access levels however I discovered that the highest level of privileges granted with the PROCESS_ALL_ACCESS option is the best when injecting.  The bInheritHandle is a simple bool where if set to true all child processes of the target parent process will also inherit this handle.  Finally the dwProcessId parameter is simply the process identifier(PID) of the local process that would be found using Task Manager.  However to make finding the PID a little easier I decided to write a simple function that would take the process name and return the process id.  

So far our DLL injection function should look like this:
```c
bool InjectDynamicLibrary(DWORD processId, char* dllPath)
{
	// Open a new handle to the target process
	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);
} 
```
<br/>
The next step in injecting a DLL is to allocate space in the target process using our handle.  To do this we are going to use Microsoft's VirtualAllocEx function.  
![virtual alloc api][virtualalloc]
<br/>
The hProcess parameter is simply for the handle that we created in the previous step.  The lpAddress allows us to specify a desired starting address for the region of space we wish to allocate for.  We are going to specifically assign this to null or zero so that we can use the MEM_COMMIT value in a later parameter.  The next parameter that we will use is dwSize which is used to specify the size of the region that we are going allocate for.  We will set this by using strlen on our dllPath to determine the size of the DLL’s path and the amount of space to reserve.  The flAllocationType parameter is used to specify the type of memory allocation we are going to use.  The MEM_COMMIT value is used to guarantee that memory will not be allocated until the caller attempts to access it and that the contents will be zero.  Additionally we are going to want to use MEM_RESERVE to safely reserve a range of virtual address space for our DLL.  Finally we are going to set the flProtect parameter to PAGE_READWRITE so the allocated space has read/write permissions.  
<br/>
<br/>
This is what your code should now look like:
```c
bool InjectDynamicLibrary(DWORD processId, char* dllPath)
{
	// Open a new handle to the target process
	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);
	if (hTargetProcess) // if the handle is valid
	{
		// Allocates more memory in the target process for our DLL.
		LPVOID LoadPath = VirtualAllocEx(hTargetProcess, 0, strlen(dllPath),
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
 	}
}
```
<br/>
<br/>
Now we will use the very intuitive WriteProcessMemory function to write the DLL to the allocated space.  
![Write Process API][writeprocessapi]
<br/>
This function is going to take our hTargetProcess handle and starting at the beginning of our LoadPath copy the location of our DLL using dllPath.  Additionally we need to specify a nSize or the number of bytes we are going to copy which in our case is just the strlen of dllPath. Finally we set the lpNumberOfBytesWritten to NULL as we have not written anything to this space yet.   This should look similar to the function call below.
```c
// Writes the dll to the allocated memory space.
bool written = WriteProcessMemory(hTargetProcess, LoadPath, (LPCVOID)dllPath, strlen(dllPath), NULL);
```
<br/>
Finally it is time to create a thread and execute our DLL using the CreateRemoteThread function.
![Create Remote Thread API][createremote]
<br/>
<br/>
The first parameter is the familiar hProcess which is yet again just the handle we created in the original step.  The lpThreadAttributes parameter allows us to determine whether the child processes inherit the thread which we will set to 0 making in non inheritable.  The dwStackSize parameter sets the stack size for the new thread which we also want set to 0 making it default to the size of the process.  The lpStartAddress indicates where in memory the thread will start executing.   In order to properly set this we are going to need to write a few lines of code. 
```c
// Kernel32.dll is always the same address in every process.
LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
```
<br/>
This grabs the process address within our process because the Kernel32.dll is the same address in every process.  It then assigns it to the LoadLibAddr variable which is then assigned to our lpStartAddress parameter.  The next parameter is the lpParameter which allows us to specify a pointer to a memory location which will get passed in as a function parameter to the function that resides at lpStartAddress.  This we will set to the LoadPath the we retrieved from the memory allocation step.  The dwCreationFlags parameter is used to start the thread in a certain manner.  We want to set this to the default of 0 which will immediately execute the thread when it is created.  Finally we have the lpThreadId which is determined when the thread is finally created. 
<br/>
```c
// Create a thread in the target process that will call LoadLibraryA() with the dllpath as a parameter
HANDLE RemoteThread = CreateRemoteThread(hTargetProcess, 0, 0, 
(LPTHREAD_START_ROUTINE)LoadLibAddr, LoadPath, 0, 0);
```
<br/>
At this point I have covered all of the important parts of the Windows API that makes DLL injection relatively simple and the remaining code is just for memory clean up.
It is important to note that Python has an incredibly fluid ctypes library which makes it easy to utilise c data types and call DLL libraries all while wrapping it with pure python code.  This makes it very simple to write a DLL injector as we can see below.
<br/>
```python
import sys
import win32api
from ctypes import *
kernel32 = win32api.kernel32

#Hardcoded globals used when interacting with the WinAPI.
PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = ( 0x000F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM = ( 0x1000 | 0x2000 )

def inject(pid, dllPath):
    dllLen = len(dllPath)

    #Create the handle to our target process.
    hTargetProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, false, int(pid))
    if not hTargetProcess:
        print("Oh boy... I could not create a handle to the process!  Your PID is: %s", PID)
        sys.exit(0)

    #Allocate memory within the process.
    loadPath = kernel32.VirtualAllocEx(hTargetProcess, 0, dllLen, VIRTUAL_MEM, PAGE_READWRITE)

    #Write to the newly created space.
    written = c_int(0)
    kernel32.WriteProcessMemory(hTargetProcess, loadPath, dllPath, dllLen, byref(written))

    hKernel32 = kernel32.GetModuleHandleA("kernel32.dll")
    hLoadlib = kernel32.GetProcAddress(hKernel32,"LoadLibraryA")

    #Create the thread and execute the DLL
    threadId = c_ulong(0)
    if not kernel32.CreateRemoteThread(hTargetProcess, None, 0, hLoadlib, loadPath, 0, byref(threadId)):
        print "Oh no... Failed to inject the DLL!"
        sys.exit(0)

    print ("Victory!  Thread with ID 0x%08x sucessfully created." % threadId.value)

def main():
    pid = input("Enter the process id: ")
    dllPath = input("Enter the path to the DLL: ")
    inject(pid, dllPath)

main()
```
<br/>
It is now time for us to inject our DLL!  This DLL is incredibly basic and simply outputs a greeting from the injected process but in the real world these can be much more dastardly.  
<br/>
![Demo Image][demo]