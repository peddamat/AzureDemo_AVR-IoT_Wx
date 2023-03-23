openssl asn1parse -genconf private-key.asn1 -out private-key.der -noout
openssl rsa -in private-key.der -inform der -out private-key.pem
openssl rsa -in private-key.pem -text -noout
