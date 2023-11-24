#!/usr/bin/python3
from os import popen
import sys

# @Author: sh1ve


ARCH = 'ELF64'
DUMP = ''
ELF = b''


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
    readelf = 'readelf -h -- '+ filename
    res = shell(readelf)
    # check elf valid
    if not res or 'ELF Header' not in res:
        return False
    strings = 'strings ' + filename + ' | grep "E: neither"'
    check = shell(strings)
    if not check:
        print('Seems not packed with shc')
        return False
    global ARCH
    if 'ELF32' in res:
        ARCH = 'ELF32'
    # get objdump
    global DUMP
    objdump = 'objdump -M intel -D -- ' + filename
    DUMP = shell(objdump)
    if not DUMP:
        return False
    return True


def shell(cmd):
    # TODO change the way to execute command
    result = popen(cmd).read()
    return result


def find_call(func_name, rindex):
    # find function call
    global DUMP
    end = DUMP.rfind(func_name)
    if end == -1:
        return b''
    # right index
    for i in range(rindex):
        end = DUMP[:end].rfind(func_name)
    # extract the binary machine code between `:` and `call` 
    start = DUMP[:end].rfind(':') + 1
    end = DUMP[:end].rfind('call')
    func_opcode = DUMP[start:end].strip()
    print('call ' + func_name + ' opcode:' + func_opcode)
    binary_code = bytes.fromhex(func_opcode)
    return binary_code


def patch_func(func_name, rindex, replace_code = ""):
    global ELF
    machine_code = find_call(func_name, 0)
    if machine_code:
        # default patched with `nop`
        if not replace_code:
            replace_code = '90 ' * len(machine_code)
        patch_code = bytes.fromhex(replace_code)
        offset = ELF.rfind(machine_code)
        machine_code = ELF[offset : offset + len(patch_code)]
        ELF = ELF.replace(machine_code, patch_code)
        print("Patch "+ func_name + " with " + replace_code)


def patch64():
    # mov eax, 1 | leave | ret
    patch_func('getpid', 0, 'B8 01 00 00 00 C9 C3')
    # mov eax,1 | mov edi, eax | syscall | xor eax, eax | leave | ret
    patch_func('memcpy', 0, 'B8 01 00 00 00 89 C7 0F 05 31 C0 C9 C3')
    patch_func('exec', 0)
    # patch exec and system avoid unexpected execution
    patch_func('system', 0)


def patch32():
    patch_func('getpid', 0, 'B8 01 00 00 00 C9 C3')
    # mov eax,4 | pop edx | push 1 | pop ebx | pop ecx | pop edx | int 80h
    # xor eax, eax | leave | ret
    patch_func('memcpy', 0, 'B8 04 00 00 00 5A 6A 01 5B 59 5A CD 80 31 C0 C9 C3')
    patch_func('exec', 0)
    # patch exec and system avoid unexpected execution
    patch_func('system', 0)


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
    output_file = open(filepath + '.patch', 'wb')
    output_file.write(ELF)


if __name__ == '__main__':
    main()
    
