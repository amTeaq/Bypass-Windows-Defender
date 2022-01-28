# Defeat Windows Defender using direct Syscall

## Protection rings


![image](https://user-images.githubusercontent.com/76106120/151554524-e5d661f2-6d22-4051-a2bf-40367cf6ac2f.png)


Windows os as some security rings in order to avoid any one to access critical memory region.
There is the user-mode where the application are running (ring 3) and the kernel mode (ring 0) with the critical system components.
Some resources cannnot be accessed by specific application in order to prevent malicious behavior.

Application are isolated from critical memory section and system resources are running in Kernel Mode.
To make the translation between user mode and kernel mode there is an dll called ntddl.dll.
Ntddl.dll gives the right Api call perform by the user mode, thanks to that the kernel can make the right system call.

In the image just below, you can see how the user mode and the kernel mode interract :
 
 ![image](https://user-images.githubusercontent.com/76106120/151557062-8362dc30-e1bf-495f-9dc9-0f046ea21b70.png)

