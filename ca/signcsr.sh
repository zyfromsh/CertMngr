type=client
name=rtu.1231231.honeywell.com
SIGNING_KEY_PASS=flatwave181
    openssl req \
        -in $type/tmp/$name.csr.der \
        -inform der \
        -out tmp/$name.csr

    openssl ca \
        -config etc/signing-ca.conf \
        -in tmp/$name.csr \
        -out certs/$name.crt \
        -extensions server_ext \
        -passin pass:$SIGNING_KEY_PASS \
        -batch

    # Certificate needs to be converted to DER format
    # before transfer back to the host that raised the
    # signing request.
    #
    openssl x509 \
        -in certs/$name.crt \
        -out certs/$name.cer \
        -outform der