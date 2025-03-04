# https://docs.openssl.org/3.3/man1/openssl-genrsa/
# https://developers.yubico.com/PIV/Guides/Generating_keys_using_OpenSSL.html
openssl genrsa -out private.pem 2048

# https://docs.openssl.org/1.1.1/man1/rsa/#description
openssl rsa -in private.pem -outform DER -out private.der
openssl rsa -in private.pem -pubout -outform DER -out public.der

# https://www.tutorialspoint.com/unix_commands/xxd.htm
xxd -i private.der > rsa_priv_key.h
xxd -i public.der > rsa_pub_key.h