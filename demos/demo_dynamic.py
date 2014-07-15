

""" 
    demo_dynamic.py                                     v1
    
    This program demonstrates Python's use of the dynamic 
    language support additions to LTC, namely access to LTC 
    constants, struct and union sizes, and the binding of a 
    math package to LTC.  Also provided are simple code 
    fragments to illustrate how one might write a Python 
    wrapper for LTC and how an app might call the wrapper. 
    This or a similar model should work for Ruby and other 
    dynamic languages.
    
    This instance uses Python's ctypes and requires a single 
    .dylib linking together LTC and a math library.  Building 
    a single .dylib is needed because LTC wants a fairly tight 
    relationship between itself and the mathlib.  (ctypes can 
    load multiple .dylibs, but it does not support this level 
    of tight coupling between otherwise independent libraries.)
    
    My .dylib was created on OSX with the following steps:
      
      1- compile LTC to a .a static lib:
           CFLAGS="-DLTM_DESC -DUSE_LTM" make
      
      2- link LTC and LTM into a single .dylib:
           ar2dylib_with  tomcrypt  tommath
         where ar2dylib_with is a shell script that combines 
         the LTC .a with the LTM .dylib
    
    Reminder: you don't need to bind in a math library unless
              you are going to use LTC functions that depend 
              on a mathlib.  For example, public key crypto 
              needs a mathlib; hashing and symmetric encryption 
              do not.
    
    This code was written for Python 2.7.
    
    Larry Bugbee
    March 2014

"""


from ctypes import *
from ctypes.util import find_library


#---------------------------------------------------------------
# load the .dylib

libname = 'tomcrypt'
libpath = find_library(libname)

print
print('  demo_dynamic.py')
print
print('  path to library %s: %s' % (libname, libpath))

LTC = cdll.LoadLibrary(libpath)
print('  loaded: %s' % LTC)
print



#---------------------------------------------------------------
# get list of all supported constants followed by a list of all 
# supported sizes.  One alternative: these lists may be parsed 
# and used as needed.

if 1:
    print '  all supported constants and their values:'
    
    # get size to allocate for constants output list
    str_len = c_int(0)
    ret = LTC.crypt_list_all_constants(None, byref(str_len))
    print '    need to allocate %d bytes \n' % str_len.value
    
    # allocate that size and get (name, size) pairs, each pair
    # separated by a newline char.
    names_sizes = c_buffer(str_len.value)
    ret = LTC.crypt_list_all_constants(names_sizes, byref(str_len))
    print names_sizes.value
    print
    
    
if 1:
    print '  all supported sizes:'
    
    # get size to allocate for sizes output list
    str_len = c_int(0)
    ret = LTC.crypt_list_all_sizes(None, byref(str_len))
    print '    need to allocate %d bytes \n' % str_len.value
    
    # allocate that size and get (name, size) pairs, each pair
    # separated by a newline char.
    names_sizes = c_buffer(str_len.value)
    ret = LTC.crypt_list_all_sizes(names_sizes, byref(str_len))
    print names_sizes.value
    print


#---------------------------------------------------------------
# get individually named constants and sizes

# print selected constants
if 1:
    print '\n  selected constants:'
    
    names = [
        'ENDIAN_LITTLE',
        'ENDIAN_64BITWORD',
        'PK_PUBLIC',
        'MAX_RSA_SIZE',
        'CTR_COUNTER_BIG_ENDIAN',
    ]
    for name in names:
        const_value = c_int(0)
        rc = LTC.crypt_get_constant(name, byref(const_value))
        value = const_value.value
        print '    %-25s  %d' % (name, value)

# print selected sizes
if 1:
    print '\n  selected sizes:'
    
    names = [
        'rijndael_key',
        'rsa_key',
        'symmetric_CTR',
        'twofish_key',
        'ecc_point',
        'gcm_state',
        'sha512_state',
    ]
    for name in names:
        size_value = c_int(0)
        rc = LTC.crypt_get_size(name, byref(size_value))
        value = size_value.value
        print '    %-25s  %d' % (name, value)


#---------------------------------------------------------------
#---------------------------------------------------------------
# ctypes getting a list of this build's supported algorithms 
# and compiler switches

def get_named_string(lib, name):
    return c_char_p.in_dll(lib, name).value

if 0:
    print '\n%s' % ('-'*60)
    print 'This is a string compiled into LTC showing compile '
    print 'options and algorithms supported by this build \n'
    print get_named_string(LTC, 'crypt_build_settings')
    print



#---------------------------------------------------------------
#---------------------------------------------------------------
# here is an example of how a wrapper can make Python access 
# more Pythonic

# - - - - - - - - - - - - -
# a wrapper fragment...

def _get_size(name):
    size = c_int(0)
    rc = LTC.crypt_get_size(name, byref(size))
    return size.value

sha256_state_struct_size = _get_size('sha256_state')
sha512_state_struct_size = _get_size('sha512_state')

class SHA256(object):
    def __init__(self):
        self.state = c_buffer(sha256_state_struct_size)
        LTC.sha256_init(byref(self.state))
    def update(self, data):
        LTC.sha256_process(byref(self.state), data, len(data))
    def digest(self):
        md = c_buffer(32)
        LTC.sha256_done(byref(self.state), byref(md))
        return md.raw

# - - - - - - - - - - - - -
# an app fragment...

# from wrapper import *         # uncomment in real life

data = 'hello world'

sha256 = SHA256()
sha256.update(data)
md = sha256.digest()

template = '\n\n  the SHA256 digest for "%s" is %s \n'
print template % (data, md.encode('hex'))



#---------------------------------------------------------------
#---------------------------------------------------------------
#---------------------------------------------------------------
