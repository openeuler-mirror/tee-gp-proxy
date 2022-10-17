#! /bin/sh

_openssl="openssl"

CUR_DIR=$( dirname -- "$0"; )


# CAKEYPEM=$HOME/.gpp/certs/ca_key.pem
# CACRTPEM=$HOME/.gpp/certs/ca_crt.pem
# KEYPEM=$HOME/.gpp/certs/server_key.pem
# CSRPEM=$HOME/.gpp/certs/server_csr.pem
# CRTPEM=$HOME/.gpp/certs/server_crt.pem
CAKEYPEM=$CUR_DIR/ca_key.pem
CACRTPEM=$CUR_DIR/ca_crt.pem
KEYPEM=$CUR_DIR/server_key.pem
CSRPEM=$CUR_DIR/server_csr.pem
CRTPEM=$CUR_DIR/server_crt.pem
RSAKEYLEN=2048
EXPIREDAYS=3650
SUBSTR="/C=CN/ST=Hubei/L=Wuhan/O=TrustCute/OU=gRPC/CN=gpserver.org"

# echo -e '\n'generate $KEYPEM: 
# $_openssl genrsa -passout pass:111111 -aes192 -out $KEYPEM ${RSAKEYLEN}
# $_openssl genrsa -aes192 -out $KEYPEM ${RSAKEYLEN}

echo -e '\n'generate certgen request $CSRPEM: 
# $_openssl req -passin pass:111111 -new -key $KEYPEM -out $CSRPEM -subj ${SUBSTR}
$_openssl req -new -key $KEYPEM -out $CSRPEM -subj ${SUBSTR}

echo -e '\n'generate $CRTPEM: 
# ${_openssl} x509 -req -passin pass:111111 -days ${EXPIREDAYS} -in $CSRPEM -CA $CACRTPEM -CAkey $CAKEYPEM -CAcreateserial -out $CRTPEM
${_openssl} x509 -req -days ${EXPIREDAYS} -in $CSRPEM -CA $CACRTPEM -CAkey $CAKEYPEM -CAcreateserial -out $CRTPEM
