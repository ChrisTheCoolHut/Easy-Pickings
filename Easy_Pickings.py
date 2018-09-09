#!/usr/bin/python3
import argparse
import r2pipe
import json
import IPython
import lief

c_template = '''
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

//For this static non-sense to work, you should run and compile on the exact same environment
//sudo ./dockcross-linux-mipsel bash -c '$CC User_Supplied_runner.c -static -O0 -fPIC -Wl,-strip-all -ldl -o User_Supplied_runner.bin'
typedef int(*check_t)(char*);

int main (int argc, char** argv) {{

  void* handler = dlopen("./{0}", RTLD_LAZY);
  check_t {1} = (check_t)dlsym(handler, "{1}");

  int output = {1}(argv[1]);

  printf("Output of {1}('%s'): %d\\n", argv[1], output);

  return 0;
}}
'''

def get_functions(binary):
    print("[~] Using Radare2 to build function list...")
    r2 = r2pipe.open(binary)
    r2.cmd('aaaa')
    return [func for func in json.loads(r2.cmd('aflj'))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('File', help="File to pull function")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--Functions', action='store_true', help="List functions in binary to choose", default=False)
    group.add_argument('--Address','-A', help="Use this address for function creation", type=lambda x: int(x,0))

    args = parser.parse_args()
    
    if args.Functions:
        funcs = get_functions(args.File)

        func_addrs = []
        for func in funcs:
            n_func = {}
            n_func['name'] = func['name']
            n_func['addr'] = func['offset']
            func_addrs.append(n_func)

        print("Choose function:")
        user_input = '-1'
        while user_input not in range(len(func_addrs)):
            for i in range(len(func_addrs)):
                print("[{:<3}] {:<40} : {}".format(i, func_addrs[i]['name'],hex(func_addrs[i]['addr'])))
            user_input = input(">>")
            if user_input.isdigit():
                user_input = int(user_input)
        func = func_addrs[user_input]
    elif args.Address:
        func = {}
        func['name'] = "User_Supplied"
        func['addr'] = args.Address
    else:
        exit(0)
    print("[+] Using {} : {}".format(func['name'], hex(func['addr'])))

    print("[+] Parsing binary {}".format(args.File))
    binary = lief.parse(args.File)
    
    print("[+] Creating export")
    binary.add_exported_function(func['addr'], func['name'])

    file_name = "lib{}.so".format(args.File)
    print("[+] Writing to file {}".format(file_name))
    binary.write(file_name)

    print("[+] Creating c runner")
    code = c_template.format(file_name, func['name'])
    c_file = "{}_runner.c".format(func['name'])
    with open(c_file, 'w') as f:
        f.write(code)

if __name__ == '__main__':
    main()
