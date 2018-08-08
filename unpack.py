from pdb import pm
import sys

from miasm2.analysis.sandbox import Sandbox_Win_x86_32
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.core.utils import pck16, pck32, upck32, hexdump, whoami
from miasm2.os_dep.win_api_x86_32 import winobjs

import wincrypt2 

# Insert here user defined methods
argc_init = False
def msvcrt___p___argc(jitter):
    global argc_init
    ret_ad, _ = jitter.func_args_cdecl(0)
    addr_argc = 0x13370000
    if not argc_init:
        jitter.vm.add_memory_page(addr_argc, PAGE_READ | PAGE_WRITE, pck32(1), "argc")
        argc_init = True
    jitter.func_ret_stdcall(ret_ad, addr_argc)

def load_res(jitter):
    ret_ad, args = jitter.func_args_stdcall(['hMod','password'])
    pwd = jitter.get_str_ansi(args.password)
    print("load ressource, hMod: %x, password: %s. Returns 1 (success)" % (args.hMod, pwd))
    jitter.func_ret_stdcall(ret_ad, 1)
    return True

def kernel32_CreateProcessA(jitter):
    ret_ad, args = jitter.func_args_stdcall(['appname', 'cmdline', 'procAttrs',
        'threadAttrs', 'inherit', 'creatFlags', 'env', 'curDir', 'startupInfo',
        'procInfos'])
    cmdline = jitter.get_str_ansi(args.cmdline)
    curDir = jitter.get_str_ansi(args.curDir) if args.curDir else ""
    print("Create process '%s' in dir '%s'" % (cmdline,curDir))
    jitter.func_ret_stdcall(ret_ad, 1)

def advapi32_CryptImportKey(jitter):
    ret_ad, args = jitter.func_args_stdcall(['hprov','data','dataLen','pubKey','flags','hKeyRet'])
    print("Import key: data=%x, len=%d, pubKey=%x, flags=%x, pkeyRet=%x" % (
        args.data, args.dataLen, args.pubKey, args.flags, args.hKeyRet))
    key = jitter.vm.get_mem(args.data, args.dataLen)
    key = wincrypt2.CryptImportKey(key)
    if key is None:
        jitter.func_ret_stdcall(ret_ad, 0)
        return

    handle = winobjs.handle_pool.add("CryptKey", key)
    jitter.vm.set_mem(args.hKeyRet, pck32(handle))
    jitter.func_ret_stdcall(ret_ad, 1)

def advapi32_CryptDecrypt(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hkey", "hhash", "final",
                                          "dwflags", "pbdata",
                                          "pdwdatalen"])
    dataLen = upck32(jitter.vm.get_mem(args.pdwdatalen, 4))
    print("CryptDecrypt: hkey = %x, data=%x, dataLen=%d" % (args.hkey, args.pbdata, dataLen))
    if not args.hkey in winobjs.handle_pool:
        jitter.func_ret_stdcall(ret_ad, 0)
        return
    key = winobjs.handle_pool[args.hkey].info

    D = jitter.vm.get_mem(args.pbdata, dataLen)
    D = wincrypt2.CryptDecrypt(key, D)
    if D is None:
        jitter.func_ret_stdcall(ret_ad, 0)
        return
    D = str(D)
    print("Decrypted data: %s" % D.encode("hex"))
    jitter.vm.set_mem(args.pbdata, D)
    jitter.vm.set_mem(args.pdwdatalen, pck32(len(D)))
    jitter.func_ret_stdcall(ret_ad, 1)

def kernel32_GetComputerNameW(jitter):
    # https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms724295(v=vs.85).aspx
    ret_ad, args = jitter.func_args_stdcall(['lpBuffer', 'lpnSize'])

    # Get buffer size from memory
    size = upck32(jitter.vm.get_mem(args.lpnSize, 4))

    # Removing one character to size, as it includes the terminal null character
    size = min(size-1, 10)
    name = "A"*(size)
    jitter.set_str_unic(args.lpBuffer, name)

    # Returned size must not include the null terminating character
    jitter.vm.set_mem(args.lpnSize, pck32(size))

    # Returns true
    jitter.func_ret_stdcall(ret_ad, 1)

def kernel32_EnterCriticalSection(jitter):
    ret_ad, args = jitter.func_args_stdcall(['CS'])
    jitter.func_ret_stdcall(ret_ad, 0)

def kernel32_LeaveCriticalSection(jitter):
    ret_ad, args = jitter.func_args_stdcall(['CS'])
    jitter.func_ret_stdcall(ret_ad, 0)

def msvcrt__local_unwind2(jitter):
    ret_ad,args = jitter.func_args_cdecl(['xr','stop'])
    jitter.func_ret_cdecl(ret_ad,0)

def kernel32_GetProcessHeap(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0xdeadbeef)


def dump_code(jitter):
    print("[+] Dump code in unpacked.dll...")
    all_ = jitter.vm.get_mem(0x20202000, 65536)
    open("unpacked.dll","w").write(all_)
    print("[+] Done!")
    sys.exit(0)

# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()

# Create sandbox
sb = Sandbox_Win_x86_32(options.filename, options, globals())

sb.jitter.add_breakpoint(0x00401dab, load_res)
sb.jitter.add_breakpoint(0x20218CDF, dump_code)

# Run
sb.run()

assert(sb.jitter.run is False)
