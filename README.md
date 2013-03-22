# libredirect

## What's that?
libredirect is a c library to hook and redirect function in run-time. This is done
by manipulating the executable memory of the proccess. It currently works on i386
and amd64 but can be extended simply (take a look at arch/x86.c).

The advantage you get by using libredirect instead of LD_PRELOAD is, that
libredirect works at run-time and you don't need controll over the start of the
proccess. You, however, have to bring the proccess to load your code and libredirect.
This can be done at run-time with code/so injection (take a look at injectso
http://c-skills.blogspot.de/2009/10/injectso-32bit-x86-port.html and hotpatch
https://github.com/vikasnkumar/hotpatch).

## Documentation
Documentation is in libredirect.h. For more information take a look at the tests
or at the source code.

## License
GPL3, see LICENSE.txt

## Build

    cmake ../path/to/libredirect
    make

libredirect uses libopcodes, which you apparently can't package. For libopcodes,
libbfd and libiberty you should use the static libraries (which is default). For
some systems you may have to compile the libraries yourself with -fPIC (they are
part of binutils). You can then set CMAKE\_LIBRARY\_PATH to the directory which
contains them.

    cmake ../path/to/libredirect -DCMAKE_LIBRARY_PATH=../libs/for/libredirect
    make

For i386 build on a amd64 host it should work with the -m32 flag (make sure you
have all libraries for i386):

    CFLAGS="-m32" cmake ../path/to/libredirect
    make


