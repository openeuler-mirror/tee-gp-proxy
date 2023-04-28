#! /bin/sh

_openssl="openssl"

CUR_DIR=$( dirname -- "$0"; )


# KEYPEM=$HOME/.teecc/certs/client_key.pem
# CSRPEM=$HOME/.teecc/certs/client_csr.pem
KEYPEM=$CUR_DIR/client_key.pem
CSRPEM=$CUR_DIR/client_csr.pem
RSAKEYLEN=2048
SUBSTR="/C=CN/ST=Hubei/L=Wuhan/O=TrustCute/OU=gRPC/CN=gpclient.org"

echo -e '\n'generate $KEYPEM: 
# $_openssl genrsa -passout pass:111111 -aes192 -out $KEYPEM ${RSAKEYLEN}
$_openssl genrsa -aes192 -out $KEYPEM ${RSAKEYLEN}

echo -e '\n'generate certgen request $CSRPEM: 
# $_openssl req -passin pass:111111 -new -key $KEYPEM -out $CSRPEM -subj ${SUBSTR}
$_openssl req -new -key $KEYPEM -out $CSRPEM -subj ${SUBSTR}

