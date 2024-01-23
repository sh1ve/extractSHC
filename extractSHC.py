#!/usr/bin/python3
from os import popen
import sys

# @Author: sh1ve


ARCH = 'ELF64'
DUMP = ''
ELF = b''
BASE = 0

def get_file():
    if len(sys.argv) < 2:
            return None
    filepath = sys.argv[1]
    try:
        with open(filepath, 'rb') as file:
            global ELF
            ELF = file.read()
            print("Read file successfully")
        return filepath
    except FileNotFoundError:
        print("File not exist")
        return None
    except IOError:
        print("Fail to open file")
        return None


def get_dump(filename):
    global ARCH, DUMP, BASE
    elf_header = 'objdump -h -- '+ filename
    res = shell(elf_header)
    # check elf valid
    if not res or 'file format elf' not in res:
        return False
    strings = 'strings ' + filename + ' | grep "E: neither"'
    check = shell(strings)
    if not check:
        print('Seems not packed with shc')
        return False
    if 'elf32' in res:
        ARCH = 'ELF32'
    # get objdump
    objdump = 'objdump -M intel -d -j .text -- ' + filename
    DUMP = shell(objdump)
    if not DUMP:
        return False
    text_start = res.find('.text')
    text_info = res[text_start:].split()
    BASE = int(text_info[2], 16) - int(text_info[4], 16)
    print("File Format: " + ARCH)
    print("Base Address: " + hex(BASE))
    return True


def shell(cmd):
    # TODO change the way to execute command
    result = popen(cmd).read()
    return result


def find_call(func_name, rindex):
    # find function call
    global DUMP, BASE
    end = DUMP.rfind(func_name)
    if end == -1:
        return 0
    # right index
    for i in range(rindex):
        end = DUMP[:end].rfind(func_name)
    # extract the offset between `\n` and `:` 
    start = DUMP[:end].rfind('\n') + 1
    end = DUMP[:end].rfind(':')
    func_offset = int(DUMP[start:end].strip(), 16) - BASE
    print('call ' + func_name + ' at offset: ' + hex(func_offset))
    return func_offset


def patch_func(func_name, rindex, replace_code = ""):
    global ELF
    offset = find_call(func_name, rindex)
    if offset:
        # default patched with `nop`
        if not replace_code:
            replace_code = '90 ' * 5
        patch_code = bytes.fromhex(replace_code)
        # replace the binary code at the offset
        ELF = ELF[:offset] + patch_code + ELF[offset + len(patch_code):]
        print("Patch "+ func_name + " with " + replace_code)
        return True
    return False


def patch64():
    # patch exec and system avoid unexpected execution
    patch_func('exec', 0)
    hard = patch_func('system', 0)
    # if system exist, the HARDENING flag is on
    if hard:
        # mov eax, 1 | leave | ret
        # if HARDENING, `getpid` in `chkenv` at rindex 1
        patch_func('getpid', 1, 'B8 01 00 00 00 C9 C3')
        patch_func('memcpy', 0, '48 89 FE 48 31 FF FF C7 48 89 F8 0F 05 B8 3C 00 00 00 0F 05')
    else:
        patch_func('getpid', 0, 'B8 01 00 00 00 C9 C3')
        # mov eax,1 | mov edi, eax | syscall | xor eax, eax | exit
        patch_func('memcpy', 0, 'B8 01 00 00 00 89 C7 0F 05 31 C0 B8 3C 00 00 00 0F 05')


def patch32():
    # patch exec and system avoid unexpected execution
    patch_func('exec', 0)
    hard = patch_func('system', 0)
    # if `system` exist, the HARDENING flag is on
    if hard:
        patch_func('getpid', 1, 'B8 01 00 00 00 C9 C3')
        # mov eax,4 | pop ecx | pop edx | pop edx | push 1| pop ebx | int 80h
        # xor eax, eax | inc eax | exit
        patch_func('memcpy', 0, 'B8 04 00 00 00 59 5A 5A 6A 01 5B CD 80 31 C0 40 C9 C3')
    else:
        patch_func('getpid', 0, 'B8 01 00 00 00 C9 C3')
        # mov eax,4 | pop edx | push 1 | pop ebx | pop ecx | pop edx | int 80h
        # xor eax, eax | inc eax | exit
        patch_func('memcpy', 0, 'B8 04 00 00 00 5A 6A 01 5B 59 5A CD 80 31 C0 40 C9 C3')


def main():
    filepath = get_file()
    if not filepath:
        print('Error in reading file')
        return None
    dump_result = get_dump(filepath)
    if not dump_result:
        print('error in objdump')
        return None
    global ARCH
    if ARCH == 'ELF64':
        patch64()
    else:
        patch32()
    new_path = filepath + '.patch'
    output_file = open(new_path, 'wb')
    output_file.write(ELF)
    shell('chmod +x ' + new_path)


if __name__ == '__main__':
    main()
    
