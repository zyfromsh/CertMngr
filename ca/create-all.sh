#!/bin/bash
#
# Create PKI (CAs, certs, and keys) intended to be used for MQTT/TLS
# with mutual authentication.
#
# The current directory should have varity of config files put in
# etc/ sub-directory. By running this script, all the other files
# will be removed and a set of fresh new ones (keys, certificates
# and crl's) will be created according to options and policy defined
# in the config files.

# Private keys for root CA and signing CA will need be protected by
# passphrase. But server and client keys will not need passphrase
# protection because they will not be used by human.
#
ROOT_KEY_PASS=flatwave239
SIGNING_KEY_PASS=flatwave181

# The domain of CA.
#
CA_DOMAIN=ca.honeywell.com

# Domain of servers and clients.
#
USER_DOMAIN=neverland.com

function create_ca_dirs {
    name=$1

    mkdir -p $name/db $name/private
    chmod 700 $name/private

    touch $name/db/$name.db $name/db/$name.db.attr
    echo 01 > $name/db/$name.crt.srl
    echo 01 > $name/db/$name.crl.srl
}

function req_ca {
    name=$1
    keydir=$2
    pass=$3

    openssl req -new \
        -config etc/$name.conf \
        -out csr/$name.csr \
        -keyout $keydir/$name.key \
        -passout pass:$pass
}

# Create CSR for server or client certificate.
#
# @param $1 FQDN of the server or client.
# @param $2 type, could be 'server' or 'client'.
# @param $3 subjectAltName, applies only to server certificate.
#
function req_cert {
    name=$1
    type=$2
    export CN=$name

    # For server certificate, it requires that the
    # subjectAltName present in the certificate
    # extension attributes.
    #
    if [ $type == "server" ]; then
        san=$3
        export SAN=$san
    fi

    openssl req -new \
        -config etc/$type.conf \
        -out $type/csr/$name.csr \
        -keyout $type/certs/$name.key

    # The PEM format CSR need to be converted
    # to DER encoded before transferred to CA
    # for signing.
    #
    openssl req \
        -in $type/csr/$name.csr \
        -out $type/tmp/$name.csr.der \
        -outform der
}

function sign_root_ca {
    openssl ca -selfsign \
        -config etc/root-ca.conf \
        -in csr/root-ca.csr \
        -out ca/root-ca.crt \
        -extensions root_ca_ext \
        -passin pass:$ROOT_KEY_PASS \
        -batch
}

function sign_signing_ca {
    openssl ca \
        -config etc/root-ca.conf \
        -in csr/signing-ca.csr \
        -out ca/signing-ca.crt \
        -extensions signing_ca_ext \
        -passin pass:$ROOT_KEY_PASS \
        -batch
}

# CA sign certificate request in DER format.
# @param $1 FQDN of the certificate, used to create filename.
#
function sign_cert {
    name=$1

    if [ -r server/tmp/$name.csr.der ]; then
        type=server
    else
        type=client
    fi

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
}

# Initialize Certificate Authorities: a root CA
# and a signing CA.
#
function init_certificate_authorities {
    mkdir -p root-ca signing-ca ca csr certs tmp
    echo Create root CA
    create_ca_dirs root-ca
    req_ca root-ca root-ca/private $ROOT_KEY_PASS
    sign_root_ca

    echo Create signing CA
    create_ca_dirs signing-ca
    req_ca signing-ca signing-ca/private $SIGNING_KEY_PASS
    sign_signing_ca
}

# Install and deploy a DER encoded PCKS#7 bundle, which contains
# trusted certificates and CRL.
# 
# @param $1 bundle file
# @param $2 type, 'server' or 'client', used to determine what folder
#           to install.
#
function install_bundle {
   echo start run bundle
    read -n 1
    bundle=$1
    type=$2

    rm -f tmp/*

    # Extract trusted certificates by recognizing the section marks.
    # Each certificate will be extracted as PEM format
    # and will be saved temporarily as {n}.tmp.crt.
    #
    openssl pkcs7 \
        -print_certs \
        -in ca/${CA_DOMAIN}.p7b \
        -inform der \
       |awk 'BEGIN {c=0; start=0} /BEGIN CERTIFICATE/{c++; start=1} /END CERTIFICATE/{start=0; print > "tmp/" c ".tmp.crt"} { if (start) print > "tmp/" c ".tmp.crt"}'

    # Renaming these {n}.tmp.crt PEM CA certificates to
    # {n}.{CA_DOMAIN}.crt
    #
    n=1
    for f in tmp/*.crt; do
        base=`basename $f`
        name=`echo ${base%.tmp.crt}`
        mv $f $type/ca/$n.${CA_DOMAIN}.crt
        n=$((n + 1))
    done

    # Extract the CRL.
    #
    openssl pkcs7 \
        -print_certs \
        -in ca/${CA_DOMAIN}.p7b \
        -inform der \
        |sed -n '/-BEGIN X509 CRL/,/-END X509 CRL/p;/-END X509 CRL/q' \
        > $type/ca/${CA_DOMAIN}.crl
}

function revoke_some_certs {
    # 02: mqtt-br2, 04: rtu2
    #
    for serial in 02 04 ; do
        openssl ca \
            -config etc/signing-ca.conf \
            -revoke signing-ca/$serial.pem \
            -crl_reason superseded \
            -passin pass:$SIGNING_KEY_PASS
    done

    openssl ca -gencrl \
        -config etc/signing-ca.conf \
        -out ca/signing-ca.crl \
        -passin pass:$SIGNING_KEY_PASS
}

# Clean everything except the config files.
#
rm -rf root-ca signing-ca ca csr certs tmp client server

if [ $1 == "clean" ]; then
    exit 0
fi

# Firstly, we need a CA chain, staring from a self-signed
# root CA to the end of a signing CA. The signing CA will
# be responsible for signing all the client and server
# certificates. There could be more than one intermediate
# CAs exist in the chain, but in this example, we use just
# two levels, i.e., root CA --> signing CA.
# 
# In our example, the CAs are in domain '${CA_DOMAIN}',
# and server/client certs are in another domain '${USER_DOMAIN}'.
#
init_certificate_authorities

# Create two folders to hold keys and certs for
# server and client.
#
for t in server client ; do
    for d in certs ca csr tmp ; do
        mkdir -p $t/$d
    done
done

# On server hosts, create key and CSR for requesting for signing.
# In the unsigned server certificate, we use DNS:{FQDN} as the
# subjectAltName.
#
# for name in \
#     mqtt-br1.${USER_DOMAIN} \
#     mqtt-br2.${USER_DOMAIN} ;
# do
#     req_cert $name server DNS:$name
# done

# On client hosts, create key and CSR for requesting for signing.
#
# for name in \
#     rtu1.${USER_DOMAIN} \
#     rtu2.${USER_DOMAIN} ;
# do
#     req_cert $name client
# done

# DER encoded CSRs are transferred to CA via e.g, email.

# CA starts to sign the certificates of server and clients.
# It needs to convert DER to PEM firstly.
#
# for name in \
#     mqtt-br1.${USER_DOMAIN} \
#     mqtt-br2.${USER_DOMAIN} \
#     rtu1.${USER_DOMAIN} \
#     rtu2.${USER_DOMAIN} ;
# do
#     sign_cert $name
# done

# Signed certificates must be transferred back to the host that
# raised the signing request and the requesting hosts must convert
# DER to PEM before use them.
#
# for f in certs/*.cer; do
#     name=`basename $f`
#     name=${name%.cer}
#     if [ -r server/csr/$name.csr ]; then
#         type=server
#     else
#         type=client
#     fi

#     openssl x509 \
#         -in $f \
#         -inform der \
#         -out $type/certs/$name.crt
# done

# Let's fictionally say, there are two certificates, mqtt-br2.${USER_DOMAIN}
# and rtu2.${USER_DOMAIN} which are revoked at some time. In real world,
# certificate revocation must happened after trusted certificates had been
# installed in the server or client, but we do the revocation now because
# we hope the trusted certificates that will be transferred to the
# server/client would already contain a CRL (Certificate Revocation List).
#
# revoke_some_certs

# Every client/server needs to install trusted certificates. In our case,
# it's root CA --> signing CA. The CA should create a PCKS#7 bundle for
# this purpose. The bundle also contains a CRL.
# The bundle needs to be in DER format before it can be transferred.
#
# openssl crl2pkcs7 \
#     -in ca/signing-ca.crl \
#     -certfile ca/root-ca.crt \
#     -certfile ca/signing-ca.crt \
#     -out ca/${CA_DOMAIN}.p7b \
#     -outform der

# Every server/client get the DER bundle of trusted certificates and CRL
# via e.g. email. Then they need to extract certificates and CRL from it
# and deploy them in PEM format.

# for t in server client ; do
#     install_bundle ca/{CA_DOMAIN}.p7b $t
#     openssl rehash $t/ca
# done

# Clean temporary files.
#
# find . -type d -name tmp -exec rm -rf {} \+

# The server and client directories now contains certificates and trust
# chain, that could be directly copy and deploy to servers and hosts.
