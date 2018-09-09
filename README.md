# Easy Pickings
Automatic function exporting and linking for fuzzing cross-architecture binaries.

This tool uses [radare2](https://rada.re/r/) to identify functions and [lief](https://lief.quarkslab.com/) to parse executables. lief is used to export these functions to shared objects (.so) to link against a stub runner. This script will further automatically create this runner and supplies an interface for selecting functions. Finally [Dockcross](https://github.com/dockcross/dockcross) is used to cross compile the stub.

Inspired by [this](https://lief.quarkslab.com/doc/latest/tutorials/08_elf_bin2lib.html) tutorial, this tool enables fast stub building for fuzzing parsing functions hidden deep in code.

## Install

### Dependencies
For function identification, this tool requires [radare2](https://github.com/radare/radare2):
```
git clone https://github.com/radare/radare2
sudo ./radare2/sys/install.sh
```
### Install Script
Docker, dockcross, leif, and r2pipe are installed from the script below
```
./install.sh
```

## Usage
Easy Pickings is a python script requiring a file and either --Functions or and address.
```
$ ./Easy_Pickings.py  -h
usage: Easy_Pickings.py [-h] (--Functions | --Address ADDRESS) File

positional arguments:
  File                  File to pull function

optional arguments:
  -h, --help            show this help message and exit
  --Functions           List functions in binary to choose
  --Address ADDRESS, -A ADDRESS
                        Use this address for function creation
```

## Example

### Running the script
Running the script with an address will not run radare2, and will immediatly create a function stub to run and link from.
```
 $ ./Easy_Pickings.py makeRequest.cgi --A 0x401210
[+] Using User_Supplied : 0x401210
[+] Parsing binary makeRequest.cgi
[+] Creating export
[+] Writing to file libmakeRequest.cgi.so
[+] Creating c runner
```
The script will produce a shared object with the exported function and a c function stub for running the function.

### Cross Compiling
For cross compiling, [Dockcross](https://github.com/dockcross/dockcross) is used to quickly cross compile. An example command is shown below:
```
$ sudo ./dockcross-linux-mipsel bash -c '$CC User_Supplied_runner.c -static -O0 -fPIC -Wl,-strip-all -ldl -o User_Supplied_runner.bin'
```
### Running the function
Since the function stub is cross compiled statically, qemu can be used to run it immediatly:
```
$ qemu-mipsel -g 4444 ./User_Supplied_runner.bin
$ afl-fuzz -i in/ -o out/ -Q -m none -- ./User_supplied_runner.bin
```

### Function stub
The stub will link the function using dlopen and dlsym and finally call the function. The script can be modified at this point to better suit your fuzzing.
```
$ cat User_Supplied_runner.c

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

//For this static non-sense to work, you should run and compile on the exact same environment
//sudo ./dockcross-linux-mipsel bash -c '$CC User_Supplied_runner.c -static -O0 -fPIC -Wl,-strip-all -ldl -o User_Supplied_runner.bin'
typedef int(*check_t)(char*);

int main (int argc, char** argv) {

  void* handler = dlopen("./libmakeRequest.cgi.so", RTLD_LAZY);
  check_t User_Supplied = (check_t)dlsym(handler, "User_Supplied");

  int output = User_Supplied(argv[1]);

  printf("Output of User_Supplied('%s'): %d\n", argv[1], output);

  return 0;
}

```
