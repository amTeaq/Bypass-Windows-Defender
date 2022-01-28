# Defeat Windows Defender using direct Syscall

## Protection rings


![image](https://user-images.githubusercontent.com/76106120/151554524-e5d661f2-6d22-4051-a2bf-40367cf6ac2f.png)


Windows os as some security rings in order to avoid any one to access critical memory region.
There is the user-mode where the application are running (ring 3) and the kernel mode (ring 0) with the critical system components.
Some resources cannnot be accessed by specific application in order to prevent malicious behavior.

Application are isolated from critical memory section and system resources are running in Kernel Mode.
To make the translation between user mode and kernel mode there is an dll called ntddl.dll.
Ntddl.dll gives the right Api call perform by the user mode, thanks to that the kernel can make the right system call.

#### In the image just below, you can see how the user mode and the kernel mode interract :
 
![image](https://user-images.githubusercontent.com/76106120/151559138-3b33e231-e4a8-4af7-a561-c34278648b02.png)
 
 
The AV/EDR products knows that the sensitive spot is when the ntdll.dll give the syscall number to execute to the kernel mode.
If an AV/EDR recognize strange syscall, they will hook the API.
 
To bypass this, it is possible to make direct system call. We can execute system call without using the ntdll.dll.
This is where the SysWhisper projet will be useful to us. With syswhisper you are able to generate file Syscall.h who contain all the syscall of each windows operating system.
SysWhisper gives us all the syscall that we need for any type of os, with that we are able to make direct syscall as if they were normal Native API functions. \n
We do not need to pass thought the ntdll.dll, a therefore to pass under the radar of AV/EDR.
 
 
 
 

