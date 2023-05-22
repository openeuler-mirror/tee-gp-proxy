#! /bin/sh

_openssl="openssl"

CUR_DIR=$( dirname -- "$0"; )


# CAKEYPEM=$HOME/.gpp/certs/ca_key.pem
# CACRTPEM=$HOME/.gpp/certs/ca_crt.pem
# CSRPEM=$HOME/.gpp/certs/client_csr.pem
# CRTPEM=$HOME/.gpp/certs/client_crt.pem
CAKEYPEM=$CUR_DIR/ca_key.pem
CACRTPEM=$CUR_DIR/ca_crt.pem
CSRPEM=$CUR_DIR/client_csr.pem
CRTPEM=$CUR_DIR/client_crt.pem
RSAKEYLEN=2048
EXPIREDAYS=3650
SUBSTR="/C=CN/ST=Hubei/L=Wuhan/O=TrustCute/OU=gRPC/CN=gpclient.org"

echo -e '\n'generate $CRTPEM: 
# ${_openssl} x509 -req -passin pass:111111 -days ${EXPIREDAYS} -in $CSRPEM -CA $CACRTPEM -CAkey $CAKEYPEM -CAcreateserial -out $CRTPEM
${_openssl} x509 -req -days ${EXPIREDAYS} -in $CSRPEM -CA $CACRTPEM -CAkey $CAKEYPEM -CAcreateserial -out $CRTPEM
