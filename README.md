# PsInspkt

PsInspkt is a command line tool that allows the user to attach to a running process and view the proces memory address space. The most useful feature of PsInspkt is the identification of pages by ID. Every page in the process address space is assigned an ID so that users can easily identif interesting pages without having to remember the page base address. 


## Features	
1. Show the  page ID and start address for each thread running in the process context along with other information.

			ProcessName: C:\Windows\SysWOW64\notepad.exe
			 EntryPoint: 0x00b4a410
			 ImageBase: 0x00b30000
			 DEP Policy: DEP Enabled
			 Number of threads: 8
			 ++++++++++++++++++++++++++++


			Thread ID: 21376
			StartAddress: 0x775940c0
			State: Alive
			StackStart: 0x0863c000
			StackEnd: 0x08640000
			Page ID: 497
			=======================


			Thread ID: 14760
			StartAddress: 0x775267c0
			State: Alive
			StackStart: 0x06c5f000
			StackEnd: 0x06c70000
			Page ID: 497
			=======================


2. Show process information

             ====PEB====
           
             PEB Address: 0x02d54000
           
             _PEB
             InheritedAddressSpace   0
             ReadImageFileExecOptions        0
             BeingDebugged   1
             BitField        4
             Mutant  0xffffffff
             ImageBaseAddress        0xb30000
             Ldr     0x775ffbe0
             ProcessParameters       0x2f00948
             SubSystemData   0x660b6a20

             ====CmdLine====
            
             C:\Windows\SysWOW64\notepad.exe
            
             ====Modules====
            
             ModuleName: C:\Windows\SysWOW64\notepad.exe     BaseAddress: 00B30000
             ModuleName: C:\Windows\SYSTEM32\ntdll.dll       BaseAddress: 774F0000
             ModuleName: C:\Windows\System32\cfgmgr32.dll    BaseAddress: 77130000
             ModuleName: C:\Windows\System32\MPR.dll BaseAddress: 71FC0000
             ModuleName: C:\Windows\System32\bcryptPrimitives.dll    BaseAddress: 74350000

            
             ====Services====
            
             ====Environment Variables====
            
             Env Var: TMP    Value: C:\Users\User\AppData\Local\Temp
             Env Var: COMPUTERNAME   Value: DESKTOP
             Env Var: VS140COMNTOOLS Value: C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools\
             Env Var: USERDOMAIN     Value: DESKTOP


3. Show all or executable only memory pages. The user can then decide whether they want to dump the page or view the start bytes by selecting a page ID.

			 ID      BaseAddress     RegionSize      Protection      Type    Module
			 19      0x00b31000      0x0001b000      R-X --- Image           C:\Windows\SysWOW64\notepad.exe
			 105     0x61a61000      0x0005e000      R-X --- Image           C:\Windows\SysWOW64\efswrt.dll


4. Search for all potential PE's in the process address space 

			 Found MZ at address: 0x00b20000
			 Associated mapped file found: C:\Windows\SysWOW64\en-US\notepad.exe.mui
			 Page ID: 17

			 Found MZ at address: 0x00b30000
			 Associated mapped file found: C:\Windows\SysWOW64\notepad.exe
			 Page ID: 18


5. Search for different ascii strings in the process address space. By default any of the search options will dump the results to a file in the current working directory of the script. For each search mode the results are displayed along with the page ID where the string was found. This is very helpful if suspicious strings are found and the user would like to dump the full page. Below is an example of searching for potential filenames in the process address space.
	* Show all potential IP addresses. Dumps results to *ip_addresses.txt*
	* Show all strings in Process Memory. Dumps results to *all_strings.txt*
	* Show all potential filenames. Dumps results to *filenames.txt*
	* Show all potential registry keys. Dumps results to *registry.txt*
	* Show all potential domain names. Dumps results to *domains.txt*

			ID 	Address 	String
			14	0xaf1d3aL	Windows\system32\cmd.exe
			14	0xaf1ef7L	Win64\bin\openssl.cfg
			14	0xaf2c93L	Windows\SysWOW64\notepad.exe



PsInspkt only supports 32-bit processes at the moment. (SysWow64 will work)



## Dependcies
PsInspkt is based on WinAppDbg. 
	`pip install winappdbg`

## Usage
	psinspkt.py <pid> attach

## Usage scenarios
PsInspkt is most useful when analysing malware or trying to identify inspect suspicious processes on a live host. The user could attach to the currently running process and dump/view the memory of that process without having to do it offline. Below are some cases where PsInspkt could be helpful.

#### Finding loaded MZ's in memory. 
In this scenario the sample being analysed was a multi-stage loader and dumping the image itself from memory only didn't show the other loaded PE in the process address space. So how did we find that there was another MZ loaded in process address space ? 

	1. First we attached to the running process by running
			psinpkt <pid> attach

	2. Second we select to inspect the process address space then we select to look for suspicious strings
			Select option:
			1-Show all commited pages
			2-Show only executable pages
			3-Search process mem for MZ
			4-Search strings in process memory
			5-Exit	

			ID      Address String

			5       0x11ef7cL       166.166.166.166
			5       0x11f59cL       166.166.166.166
			11      0x2c813cL       166.166.166.166
			11      0x2c84a0L       166.166.166.166
			11      0x2e38ccL       166.166.166.166
			13      0x41556cL       166.166.166.166
			16      0x6013c8L       166.166.166.166

	3. We can see from the output several interesting IP addresses and the page ID's where those IP addresses were found. 

	4. We can then see all commited pages to view what these pages look like 

			ID      BaseAddress     RegionSize      Protection      Type    Module
			0       0x00010000      0x00010000      RW- --- Mapped
			1       0x00020000      0x00001000      RW- --- Private
			2       0x00030000      0x00004000      R-- --- Mapped
			3       0x00040000      0x00001000      R-- --- Mapped
			4       0x0011c000      0x00001000      RW- G-- Private
			5       0x0011d000      0x00033000      RW- --- Private
			6       0x00150000      0x00001000      RW- --- Private
			7       0x00160000      0x00067000      R-- --- Mapped          C:\Windows\System32\locale.nls
			8       0x001d0000      0x00009000      R-- --- Mapped
			9       0x00290000      0x00003000      R-- --- Mapped
			10      0x002a0000      0x00001000      RW- --- Private
			11      0x002b0000      0x00037000      RW- --- Private
			12      0x003c0000      0x00001000      RW- --- Private
			13      0x00400000      0x00020000      RWX --- Private
			14      0x00420000      0x00101000      R-- --- Mapped
			15      0x005a0000      0x00001000      RW- --- Private
			16      0x00600000      0x00010000      RW- --- Private
			17      0x00610000      0x000af000      R-- --- Mapped
			18      0x0130d000      0x00002000      RW- G-- Private
			19      0x0130f000      0x00001000      RW- --- Private
			20      0x013e0000      0x00001000      R-- --- Image           C:\samples\sample.exe
			21      0x013e2000      0x00046000      R-X --- Image           C:\samples\sample.exe
			22      0x01428000      0x00001000      R-- --- Image           C:\samples\sample.exe
			23      0x0142a000      0x00001000      R-- --- Image           C:\samples\sample.exe

	5. Let's inspect Page ID 5 

			Select option
			1- Dump region
			2- View start bytes
			>2
			0011D000: 00 00 00 00 00 00 00 00  ........
			0011D008: 00 00 00 00 00 00 00 00  ........
			0011D010: 00 00 00 00 00 00 00 00  ........
			0011D018: 00 00 00 00 00 00 00 00  ........
			0011D020: 00 00 00 00 00 00 00 00  ........
			0011D028: 00 00 00 00 00 00 00 00  ........
			0011D030: 00 00 00 00 00 00 00 00  ........
			0011D038: 00 00 00 00 00 00 00 00  ........
			0011D040: 00 00 00 00 00 00 00 00  ........
			0011D048: 00 00 00 00 00

	6. Nothing interesting here. Since we are looking for a page that would start with an MZ header. Let's search for MZ's in the process address space to see if we can correlate the output from there from the interesting string search output.

			Found MZ at address: 0x00400000
			Page ID: 13
			Found MZ at address: 0x013e0000
			Associated mapped file found: C:\samples\sample.exe
			Page ID: 20

	7. Interesting ! So Page ID 13 looks like an MZ and it contained an interesting IP address match ! Let's verify that.

			>13
			Select option
			1- Dump region
			2- View start bytes
			>2
			00400000: 4d 5a 90 00 03 00 00 00  MZ......
			00400008: 04 00 00 00 ff ff 00 00  ........
			00400010: b8 00 00 00 00 00 00 00  ........
			00400018: 40 00 00 00 00 00 00 00  @.......
			00400020: 00 00 00 00 00 00 00 00  ........
			00400028: 00 00 00 00 00 00 00 00  ........
			00400030: 00 00 00 00 00 00 00 00  ........
			00400038: 00 00 00 00 80 00 00 00  ........
			00400040: 0e 1f ba 0e 00 b4 09 cd  ........
			00400048: 21 b8 01 4c cd

	8. Nice. Now you can dump the loaded PE and analyse it offline. 

