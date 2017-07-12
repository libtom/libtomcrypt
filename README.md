libtomcrypt
==========

See `doc/crypt.pdf` for a detailed documentation

Project Status
--------------

develop: [![Build Status](https://api.travis-ci.org/libtom/libtomcrypt.png?branch=develop)](https://travis-ci.org/libtom/libtomcrypt) [![Coverage Status](https://coveralls.io/repos/libtom/libtomcrypt/badge.png?branch=develop)](https://coveralls.io/r/libtom/libtomcrypt) [![Coverity Scan Build Status](https://scan.coverity.com/projects/487/badge.svg)](https://scan.coverity.com/projects/487)

Submitting patches
------------------

Please branch off from develop if you want to submit a patch.

Patch integration will be faster if tests and documentation are included.

Please update the makefiles in a separate commit. To update them simply run the `updatemakes.sh` script.

Branches
--------

Please be aware, that all branches besides _master_ and _develop_ __can__ and __will be__ force-pushed, rebased and/or removed!

If you want to rely on such an _unstable_ branch, create your own fork of this repository to make sure nothing breaks for you.

Building
--------

If you have `libtommath` installed on your system:

    make CFLAGS="-DUSE_LTM -DLTM_DESC" EXTRALIBS="-ltommath" all

For building a shared library use:

    make -f makefile.shared CFLAGS="-DUSE_LTM -DLTM_DESC" EXTRALIBS="-ltommath" all

If you have `libtommath` in a non-standard location:

    make CFLAGS="-DUSE_LTM -DLTM_DESC -I/opt/devel/ltm" EXTRALIBS="/opt/devel/ltm/libtommath.a" all

On unusual UNIX platforms, or if you do not have GNU make, have a look at `makefile.unix`.

On MS Windows try `libtomcrypt_VS2008.sln` (Visual Studio) or `makefile.mingw` or `makefile.msvc`.
