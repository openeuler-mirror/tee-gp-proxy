#! /bin/sh

_openssl="openssl"

CUR_DIR=$( dirname -- "$0"; )


# CAKEYPEM=$HOME/.gpp/certs/ca_key.pem
# CACRTPEM=$HOME/.gpp/certs/ca_crt.pem
CAKEYPEM=$CUR_DIR/ca_key.pem
CACRTPEM=$CUR_DIR/ca_crt.pem
RSAKEYLEN=2048
EXPIREDAYS=3650
SUBSTR="/C=CN/ST=Hubei/L=Wuhan/O=TrustCute/OU=gRPC/CN=ca.org"

# echo -e '\n'generate $CAKEYPEM: 
# $_openssl genrsa -passout pass:111111 -aes192 -out $CAKEYPEM ${RSAKEYLEN}
# $_openssl genrsa -aes192 -out $CAKEYPEM ${RSAKEYLEN}

echo -e '\n'generate $CACRTPEM: 
# $_openssl req -passin pass:111111 -new -x509 -days 3650 -key $CAKEYPEM -out $CACRTPEM -subj ${SUBSTR}
$_openssl req -new -x509 -days ${EXPIREDAYS} -key $CAKEYPEM -out $CACRTPEM -subj ${SUBSTR}
