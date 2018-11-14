#!/usr/bin/env python3

import ctypes, struct, binascii, os, socket
from keystone import *

#####################################################
#                                                   #
#             Python Assembler IDE                  #
#           Written by Philippe Dugre               #
#                                                   #
#####################################################


# This script requires keystone to generate the shellcode,
# but it can easily be compiled with nasm with a few modifications.


# Function to format shellcode to a printable output. Currently python3 formatting.
# Modify according to the language you use.
def format_shellcode(shellcode):
    LINE_LENGTH=40
    raw = binascii.hexlify(shellcode)
    escaped = (b"\\x" + b"\\x".join(raw[i:i+2] for i in range (0, len(raw), 2))).decode('utf-8')
    lines = [escaped[i: i+LINE_LENGTH] for i in range(0, len(escaped), LINE_LENGTH)]
    return "shellcode = \tb\"" + "\"\nshellcode += \tb\"".join(lines) + "\""


def main():
    # Shellcode is here
    # Dummy shellcode which doesn't do anything useful
    assembly = (
        "start:                              "
        "   int3                            ;"      # Debugger breakpoint.
        "   mov rax, 10                     ;"      # Equivalent to RAX = 10
        "   push rax                        ;"      # Pushes RAX on the stack
        "   pop rbx                         ;"      # Pop the last value(RAX) into RBX
        "   int3                            ;"      # If no debugger attached, int3 crashes everything
    )

    engine = Ks(KS_ARCH_X86, KS_MODE_64)
    shellcode, count = engine.asm(assembly)
    shellcode = bytearray(shellcode) # Needs to be mutable for later

    print("Number of instructions: " + str(count))

    # Print shellcode in a copy-pasteable format
    print()
    print("Shellcode length: %d" % len(shellcode))
    print()
    print(format_shellcode(shellcode))
    print()

    #####################################################################
    #                   TESTING THE SHELLCODE                           #
    #####################################################################

    # The rest of the script is used to test the shellcode. Don't run this if you just need the shellcode


    # Leave time to attach the debugger
    print("If you want to debug, attach the debugger to the python process with pid %d then press enter." % os.getpid())
    input()

    # Load libraries
    libc = ctypes.cdll.LoadLibrary("libc.so.6")
    libpthread = ctypes.cdll.LoadLibrary("libpthread.so.0")

    # Put the shellcode into a ctypes valid type.
    shellcode = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    # Both function returns 64bits pointers
    libc.malloc.restype = ctypes.POINTER(ctypes.c_int64)
    libc.mmap.restype = ctypes.POINTER(ctypes.c_int64)

    # Get page size for mmap
    page_size = libc.getpagesize()

    # mmap acts like malloc, but can also set memory protection so we can create a Write/Execute shellcodefer
    # void *mmap(void *addr, size_t len, int prot, int flags,
    #   int fildes, off_t off);
    ptr = libc.mmap(ctypes.c_int64(0),      # NULL
            ctypes.c_int(page_size),        # Pagesize, needed for alignment
            ctypes.c_int(0x07),             # Read/Write/Execute: PROT_READ | PROT_WRITE | PROT_EXEC
            ctypes.c_int(0x21),             # MAP_ANONYMOUS | MAP_SHARED
            ctypes.c_int(-1),               # No file descriptor
            ctypes.c_int(0))                # No offset

    # Copy shellcode to newly allocated page.
    libc.memcpy(ptr,                        # Destination of our shellcode
                shellcode,                        # Shellcode location in memory
                ctypes.c_int(len(shellcode)))     # Nomber of bytes to copy

    # Allocate space for pthread_t object.
    # Note that pthread_t is 8 bytes long, so we'll treat it as an opaque int64 for simplicity
    thread = libc.malloc(ctypes.c_int(8))

    # Create pthread in the shellcodefer.
    # int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    #   void *(*start_routine) (void *), void *arg);
    libpthread.pthread_create(thread,       # The pthread_t structure pointer where the thread id will be stored
                            ctypes.c_int(0),# attributes = NULL
                            ptr,            # Our shellcode, which is what we want to execute
                            ctypes.c_int(0))# NULL, as we don't pass arguments

    # Wait for the thread.
    # int pthread_join(pthread_t thread, void **retval);
    libpthread.pthread_join(thread.contents,# Here, we pass the actual thread object, not a pointer to it
                        ctypes.c_int(0))# Null, as we don't expect a return value


if(__name__ == "__main__"):
    main()

