@rem Convert a PEM certificate to PKCS12 using OpenSSL

@rem openssl pkcs12 -export -out %1.pfx -inkey %1.pem -in %1.pem -certfile ca.pem
openssl pkcs12 -export -out %1.pfx -inkey %1.pem -in %1.pem 
