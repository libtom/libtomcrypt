#!/bin/bash
# aes_tab.o is a pseudo object as it's made from aes.o and MPI is optional
export a=`echo -n "src/ciphers/aes/aes_enc.o " ; find src -type f -name "*.c" | sort | grep -v "mpi[.]c" | sed -e 's/\.c/\.o/' | xargs`
perl ./parsenames.pl OBJECTS "$a"
export a=`find src/headers -type f -name "*.h" | xargs`
perl ./parsenames.pl HEADERS "$a"

# $Source: /cvs/libtom/libtomcrypt/genlist.sh,v $   
# $Revision: 1.4 $   
# $Date: 2005/07/17 23:15:12 $ 
