# pkcs8 without password
openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt -in ../test.key -out key_pkcs8.der

# password protected - PBES1
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v1 PBE-MD2-RC2-64  -out key_pkcs8_pbe_md2_rc2_64.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v1 PBE-MD2-DES     -out key_pkcs8_pbe_md2_des.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v1 PBE-MD5-DES     -out key_pkcs8_pbe_md5_des.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v1 PBE-SHA1-RC2-64 -out key_pkcs8_pbe_sha1_rc2_64.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v1 PBE-MD5-RC2-64  -out key_pkcs8_pbe_md5_rc2_64.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v1 PBE-SHA1-DES    -out key_pkcs8_pbe_sha1_des.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v1 PBE-SHA1-3DES   -out key_pkcs8_pbe_sha1_3des.der

# password protected - PBES2
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 rc2  -out key_pkcs8_pbkdf2_rc2_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 des  -out key_pkcs8_pbkdf2_des_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 des3 -out key_pkcs8_pbkdf2_des_ede3_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 des3 -v2prf hmacWithSHA224 -out key_pkcs8_pbkdf2_sha224_des_ede3_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 des3 -v2prf hmacWithSHA256 -out key_pkcs8_pbkdf2_sha256_des_ede3_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 des3 -v2prf hmacWithSHA384 -out key_pkcs8_pbkdf2_sha384_des_ede3_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 des3 -v2prf hmacWithSHA512 -out key_pkcs8_pbkdf2_sha512_des_ede3_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 aes128 -v2prf hmacWithSHA512 -out key_pkcs8_pbkdf2_sha512_aes128_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 aes192 -v2prf hmacWithSHA512 -out key_pkcs8_pbkdf2_sha512_aes192_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 aes256 -v2prf hmacWithSHA512 -out key_pkcs8_pbkdf2_sha512_aes256_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 aes256 -v2prf hmacWithSHA512-224 -out key_pkcs8_pbkdf2_sha512_224_aes256_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 aes256 -v2prf hmacWithSHA512-256 -out key_pkcs8_pbkdf2_sha512_256_aes256_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 rc2-40 -v2prf hmacWithSHA512 -out key_pkcs8_pbkdf2_sha512_rc2_40_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 rc2-40 -v2prf hmacWithSHA512-256 -out key_pkcs8_pbkdf2_sha512_256_rc2_40_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 rc2-64 -v2prf hmacWithSHA512 -out key_pkcs8_pbkdf2_sha512_rc2_64_cbc.der
openssl pkcs8 -topk8 -inform PEM -outform DER -passout pass:secret -in ../test.key -v2 rc2-64 -v2prf hmacWithSHA512-256 -out key_pkcs8_pbkdf2_sha512_256_rc2_64_cbc.der
