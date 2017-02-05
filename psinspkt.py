import sys
import ctypes
import signal
import argparse


from winappdbg import *
from lib.objects import DProcess

__author__ = "Ahmed Zaki"
__date__ = 'Feb - 2017'


def start_proc(arg):
    procname = sys.argv[1:]
    cmd_line = System().argv_to_cmdline(procname)
    proc = System().start_process(cmd_line)
    return proc


def prompt_1():
    """
        Prompt for top level options
        Sanity checking the option provided
    :return: Valid option (int) or None
    """
    try:
        print "Select option:\n1- Inspect Process Memory Map \n2- Show process information\n" \
              "3- Exit"
        option = int(raw_input(">"))
    except ValueError as e:
        print "Invalid value. %s" % e
        return None
    if option not in [1, 2, 3]:
        print "Invalid option please select 1, 2 or 3"
        return None
    else:
        return option


def prompt_view_dump():
    """
        Prompt to either view or dump memory region selected
    :return:
    """
    try:
        print "Select option\n1- Dump region\n2- View start bytes"
        option = int(raw_input(">"))

    except ValueError as e:
        print "Invalid value. %s" % e
        return None
    if option not in [1,2]:
        print "Invalid option please select 1, 2, or 3"
        return None
    else:
        return option


def search_mz(process):

    pMatches = process.search_bytes('4d5a') # MZ
    for pMatch in pMatches:
        minAddress = pMatch[0]
        #This program
        dosheader = process.search_bytes('546869732070726f6772616d20', minAddress, minAddress+100)
        if dosheader:
            print "Found MZ at address: 0x%08x" % minAddress
            mappedFiles = process.get_mapped_files()
            if minAddress in mappedFiles:
                print "Associated mapped file found: %s" % mappedFiles[minAddress]

            pgId = process.find_page_id(minAddress)
            if not pgId:
                print "Could not locate page !"
            else:
                print "Page ID: %d" % process.find_page_id(minAddress)

    return True


def prompt_page_view():
    """
        Prompt for view memory options
        Sanity checking the option provided
    :return: Valid option (int) or None
    """

    try:
        print "Select option:\n1- Show all commited pages\n" \
              "2- Show only executable pages\n" \
              "3- Search process mem for MZ\n4- Exit\n"
        option = int(raw_input(">"))
    except ValueError as e:
        print "Invalid option. %s" % e
        return None

    if option not in [1, 2, 3, 4]:
        print "Invalid option provided."
        return None
    else:
        return option


def prompt_id(process):
    """

    :return: Memory region ID (int) or None
    """
    try:
        print "Enter memory region ID to inspect\n"
        id = int(raw_input(">"))
    except ValueError as e:
        print "Invalid value. %s" % e
        return None

    if id not in process.memMap:
        print "Unknown id. Please select a valid memory region id"
        return None
    else:
        return id


def view_proc_mem(process):
    """
        View/Dump process memory
    :param process: The DProcess object
    :return: Bool for success/fail
    """

    option = prompt_page_view()
    if option == 1: ## View all mem regions
        process.print_mem_map()
        id = prompt_id(process)
        if not id:
            return False
        b_option = prompt_view_dump()
        if not b_option:
            return False
        elif b_option == 1:
            data = process.read_mem(process.memMap[id]["BaseAddress"], process.memMap[id]["Size"])
            if not data:
                return False
            filename = hex(process.memMap[id]["BaseAddress"]) + '.bin'
            with open(filename, 'wb') as fh:
                fh.write(data)
            print "Dumped region in file: %s" % filename
            return True
        elif b_option == 2:
            data = process.read_mem(process.memMap[id]["BaseAddress"], process.memMap[id]["Size"])
            if not data:
                return False
            print process.hexdump(data, process.memMap[id]["BaseAddress"])[:420]
            return True

    elif option == 2: ## View only executable pages
        process.print_mem_map(xonly=True)
        id = prompt_id(process)
        if not id:
            return False
        b_option = prompt_view_dump()
        if not b_option:
            return False
        elif b_option == 1:
            data = process.read_mem(process.memMap[id]["BaseAddress"], process.memMap[id]["Size"])
            if not data:
                return False
            filename = hex(process.memMap[id]["BaseAddress"]) + '.bin'
            with open(filename, 'wb') as fh:
                fh.write(data)
            print "Dumped region in file: %s" % filename
            return True
        elif b_option == 2:
            data = process.read_mem(process.memMap[id]["BaseAddress"], process.memMap[id]["Size"])
            if not data:
                return False
            print process.hexdump(data, process.memMap[id]["BaseAddress"])[:420]
            return True

    elif option == 3: ## Search MZ
        search_mz(process)
        return True
    else:
        print "Invalid option please select 1, 2 or 3"
        return False


def process_info(process):

    print "\n====PEB====\n"
    pebAddress, pebstruct = process.get_peb_struct()
    print "PEB Address: 0x%08x\n" % pebAddress
    print "_PEB"
    for field_name, field_type in pebstruct._fields_:
        val = getattr(pebstruct, field_name)
        if val:
            if field_type in [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulonglong]:
                val = hex(val).rstrip('L')
        print "{0}\t{1}".format(field_name, val)

    print "\n====CmdLine====\n"
    print process.get_cmd_line()
    print "\n====Modules====\n"
    for module in process.get_modules():
        print "ModuleName: {0}\tBaseAddress: {1}".format(module["ModuleName"], module["BaseAddress"])
    print "\n====Services====\n"
    for service in process.get_services(): print service
    print "\n====Environment Variables====\n"
    for env, value in process.get_environment().iteritems():
        print "Env Var: {0}\tValue: {1}".format(env, value)

    ## PEB information

    return True


def option_prompt2(process):
    """
        First prompt. Select to inspect process memory or show process info
    :param process:
    :return:
    """
    option = prompt_1()
    if option == 1:
        return view_proc_mem(process)
    elif option == 2:
        process_info(process)
    elif option == 3:
        return False


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="The process ID to attach to")

    argv = parser.parse_args()

    pid = argv.pid

    zProcess = DProcess(pid)

    def signal_handler(signum, stack):
        zProcess.detach()

    signal.signal(signal.SIGINT, signal_handler)

    zThreads = zProcess.get_threads()
    print "ProcessName: %s" % zProcess.procname
    print "EntryPoint: 0x%08x" % zProcess.get_ep()
    print "ImageBase: 0x%08x" % zProcess.imagebase
    print "DEP Policy: %s " % zProcess.get_dep_policy()
    print "Number of threads: %d" % len(zThreads.keys())
    print "++++++++++++++++++++++++++++\n"

    for tid in zThreads:
        print "Thread ID: %d" % tid
        print "StartAddress: 0x%08x" % zThreads[tid]["StartAddress"]
        print "State: %s" % zThreads[tid]["State"]
        print "StackStart: 0x%08x" % zThreads[tid]["StackStart"]
        print "StackEnd: 0x%08x" % zThreads[tid]["StackEnd"]
        print "Page ID: %d" % zProcess.find_page_id(zThreads[tid]["StartAddress"])
        print "=======================\n"

    state = True
    while(state):
        state = option_prompt2(zProcess)

    zProcess.detach()


if __name__ == "__main__":
    main()