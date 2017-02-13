from winappdbg import *
from ctypes import *

__author__ = 'Ahmed Zaki'
__date__ = 'Feb - 2017'

SERVICE_STATES = {win32.SERVICE_CONTINUE_PENDING: "RESTARTING", win32.SERVICE_PAUSE_PENDING: "PAUSING",
                win32.SERVICE_PAUSED: "PAUSED", win32.SERVICE_RUNNING: "RUNNING",
                win32.SERVICE_START_PENDING: "STARTING", win32.SERVICE_STOP_PENDING: "STOPPING",
                win32.SERVICE_STOPPED: "STOPPED"}

SERVICE_TYPES = {win32.SERVICE_INTERACTIVE_PROCESS: "Win32 GUI", win32.SERVICE_WIN32: "Win32",
               win32.SERVICE_DRIVER: "Driver"}

DEP_FLAGS = {win32.PROCESS_DEP_ENABLE: "DEP Enabled",
             win32.PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION: "DEP-ATL Thunk emulation disabled"}

ThreadQuerySetWin32StartAddress = 9


class DProcess:

    def __init__(self, pid=None):

        try:
            print "Intialising ..."
            self._dbg = Debug()
            self._proc = self._dbg.attach(pid)
            self._proc.suspend()
            self._memsnapshot = self._proc.generate_memory_snapshot()
            self.memMap = self._read_mem_map()
            self.procname = self._proc.get_image_name()
            self.imagebase = self._proc.get_image_base()
            self._ptrPEB = self._proc.get_peb_address()
            self.ascii = self._proc.strings(minSize=7)
            self.threads = {}
            self.modules = []
            self.services = []
        except WindowsError as e:
            print "Could not attach to process. %s" % e

    def detach(self):
        """
            Detach the debugger from the process
        """
        try:
            print "\nDetaching debugger ...."
            self._proc.resume()
            Debug().detach(self._proc.dwProcessId)
        except WindowsError as e:
            print "Error. Could not detach debugger: %s" % e

    def get_main(self):
        """
            Returns the base address of the process's main image (imagebase)
        :return: int
        """
        self.main = self._proc.get_main_module()
        return self.main.lpBaseOfDll

    def get_mapped_files(self):
        """
            Returns the list of mapped files in the current memory map of the process
        :return: dict of (int,str)
        """
        self.filenames = self._proc.get_mapped_filenames()
        return self.filenames

    def get_ep(self):
        """
            Returns the EP of the process
        :return: Returns the EntryPoint of the process (int)
        """
        self.entrypoint = self._proc.get_entry_point()
        return self.entrypoint

    def get_threads(self):
        """
            Returns the list of threads
        :return: dict of dicts
        """
        self._proc.scan_threads()
        for thread in self._proc.iter_threads():
            self.threads[thread.get_tid()] = self.get_thread_info(thread.get_tid())

        return self.threads

    def get_thread_info(self, tid):
        """
            Given a TID returns a dict of thread information
        :param tid: int
        :return: dict {TebAddress(int), State(bool), StackStart(int), StackEnd(int), StartAddress(int)}
        """
        threadInfo = {}
        addr = []
        mThread = self._proc.get_thread(tid)
        tebAddr = mThread.get_teb_address()
        threadInfo["TebAddress"] = tebAddr
        if mThread.is_alive():
            threadInfo["State"] = "Alive"
        else:
            threadInfo["State"] = "Suspended"
        (stkStart, stkEnd) = mThread.get_stack_range()
        threadInfo["StackStart"] = stkStart
        threadInfo["StackEnd"] = stkEnd
        hThread = mThread.get_handle()
        buf = win32.ntdll.NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, sizeof(c_ulong))
        for char in buf:
            addr.append(ord(char))
        addr = addr[::-1]
        addr = ''.join('{:02x}'.format(x) for x in addr)
        threadInfo["StartAddress"] = int(addr, 16)

        return threadInfo

    def get_modules(self):
        """
            Returns the list of modules loaded in the process
        :return: list of dicts {BaseAddress (int), ModuleName(str)}
        """
        for module in self._proc.iter_modules():
            self.modules.append({"BaseAddress": HexDump.address(module.get_base(), self._proc.get_bits()),
                                 "ModuleName": module.get_filename()})
        return self.modules

    def get_services(self):
        """
            Returns the list of services that are running in this process
        :return: list of win32.ServiceStatusProcessEntry
        """
        for service in self._proc.get_services():
            self.services.append(service)
        return self.services

    def get_cmd_line(self):
        """
            Returns the string of the command line of a process
        :return:
        """
        return self._proc.get_command_line()

    def get_environment(self):
        """
            Returns the environment variables associated with a process
        :return: list of tuples(variable (str), value (str))
        """
        return self._proc.get_environment()

    def get_peb_struct(self):
        """
            Retrieves the PEB address and the PEB structure
        :return:
        """
        self._peb_struct = self._proc.read_structure(self._ptrPEB, win32.PEB)
        return self._ptrPEB, self._peb_struct

    def get_dep_policy(self):
        """
            Returns a tuple (int,int)
        """
        try:
            for key in DEP_FLAGS.keys():
                if self._proc.get_dep_policy()[0] & key:
                    return DEP_FLAGS[key]

            return "Disabled"
        except WindowsError as e:
            print "Could not get DEP policy. This function only works for 32bit processes. %s" % e
            return None

    def read_mem(self, addr, len):
        """
            Returns  a block of memory
        """
        try:
            return self._proc.read(addr, len)
        except WindowsError as e:
            print "Could not read memory. %s" % e
            return None

    def _get_page_protection(self, mask):
        """
            Given a page protection mask return a string describing the protection on the page
        :param mask (int)
        :return: (str)
        """
        protect = ""
        if  mask & win32.PAGE_NOACCESS:
            protect = "--- "
        elif mask & win32.PAGE_READONLY:
            protect = "R-- "
        elif mask & win32.PAGE_READWRITE:
            protect = "RW- "
        elif mask & win32.PAGE_WRITECOPY:
            protect = "RC- "
        elif mask & win32.PAGE_EXECUTE:
            protect = "--X "
        elif mask & win32.PAGE_EXECUTE_READ:
            protect = "R-X "
        elif mask & win32.PAGE_EXECUTE_READWRITE:
            protect = "RWX "
        elif mask & win32.PAGE_EXECUTE_WRITECOPY:
            protect = "RCX "
        else:
            protect = "??? "

        if mask & win32.PAGE_GUARD:
            protect += "G"
        else:
            protect += "-"
        if mask & win32.PAGE_NOCACHE:
            protect += "N"
        else:
            protect += "-"
        if mask & win32.PAGE_WRITECOMBINE:
            protect += "W"
        else:
            protect += "-"

        return protect

    def _read_mem_map(self):
        """
            Reads the memory map of the current process populating memMap wioth an ID for each page
            Only commited pages are indexed
        :return:
            Dict: {Mbi, BaseAddress, Size, State, Protection, Type}
        """
        memMap = {}
        id = 0
        for mbi in self._memsnapshot:
            bAddr = mbi.BaseAddress
            mSize = mbi.RegionSize

            # We only want commited regions
            if mbi.State == win32.MEM_COMMIT:
                state   = "Commited"
            else:
                continue

            # Page protection bits (R/W/X/G).
            if mbi.State != win32.MEM_COMMIT:
                protect = "          "
            else:
                protect = self._get_page_protection(mbi.Protect)

            # Type (file mapping, executable image, or private memory).
            if   mbi.Type == win32.MEM_IMAGE:
                type    = "Image     "
            elif mbi.Type == win32.MEM_MAPPED:
                type    = "Mapped    "
            elif mbi.Type == win32.MEM_PRIVATE:
                type    = "Private   "
            elif mbi.Type == 0:
                type    = "Free      "
            else:
                type    = "Unknown   "

            memMap[id] = {"MBI": mbi, "BaseAddress": bAddr, "Size": mSize, "State": state, "Protection": protect,
                                "Type": type}
            id+=1

        return memMap

    def hexdump(self, data, address):

        return HexDump.hexblock(data, address)

    def search_bytes(self, bytes, minAddr=None, maxAddr=None):
        """
            Search for a hex byte pattern in the process memory
        :param bytes: (str) Hex pattern of bytes to search for. wild cards are acceptable
            e.g "5? 5? c3"          # pop register / pop register / ret
        :return:
            list of tuples (int, str)
        """
        matches = []
        try:

            for address, seq in self._proc.search_hexa(bytes, minAddr, maxAddr):
                matches.append((address, seq))

        except ValueError as e:
            print "ValueError: Invalid hex sequence provided. '%s'" % e
            return None

        if not matches:
            return None
        else:
            return matches

    def search_strings(self, string, minAddr=None, maxAddr=None):
        """

        :param string: str or unicode string to search for
               encoding: If Unicode text to search for provide encoding otherwise none
               case: Bool. If non then search is case-insensitive
        :return: list of tuples Address, Match (int, str)
        """
        matches = []
        try:

            for address, text in self._proc.search_text(string, minAddr, maxAddr):
                matches.append((address, text))
        except ValueError as e:
            print "ValueError: Invalid string sequence to search for. '%s'" % e
            return None

        if not matches:
            return None
        else:
            return matches

    def print_mem_map(self, xonly=None):
        """
            Prints commited memory regions with mapped module names if found
        :return: None
        """

        mappedFiles = self.get_mapped_files()
        print "ID\tBaseAddress\tRegionSize\tProtection\tType\tModule"
        for id, mbi in self.memMap.iteritems():
            if mbi["State"] == "Commited":
                if mbi["BaseAddress"] in mappedFiles.keys():
                    name = mappedFiles[mbi["BaseAddress"]]
                else:
                    name = " "

                if xonly: ## Skip printing the page if executable only pages are requested
                    if 'X' not in mbi["Protection"]:
                        continue
                fmt = "%d\t0x%08x\t0x%08x\t%s\t%s\t%s"
                print fmt % (id, mbi["BaseAddress"], mbi["Size"], mbi["Protection"], mbi["Type"], name)

    def find_page_id(self, address):
        """
            Takes an address and returns an ID of the memory page the address lies in
        :param: address (int)
        :return: id (int)
        """

        ## Check if address is valid
        if not self._proc.is_address_valid(address):
            print "Invalid address"
            return None

        for id, dMbi in self.memMap.iteritems():
            mbi = dMbi["MBI"]
            endAddr = mbi.BaseAddress + mbi.RegionSize
            if (address >= mbi.BaseAddress) and (address <= endAddr):
                return id

        return None

    def search_reg(self, regex):
        """
            Given a regex return matches
        :return:
        """
        return self._proc.search_regexp(regex)
