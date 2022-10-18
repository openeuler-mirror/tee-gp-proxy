#! /bin/sh
# Purpose: Alert sysadmin/developer about the interity of key in advance
# Author:   under license
# -------------------------------------------------------------------------------


_openssl="openssl"


# KEYPEM=$HOME/.gpp/certs/client_key.pem
# PUBPEM=$HOME/.gpp/certs/client_pubkey.pem
# CRTPEM=$HOME/.gpp/certs/client_crt.pem
# MSGTXT=$HOME/.gpp/certs/msg.txt
# MSGSIG=$HOME/.gpp/certs/msg.sig
# GENKEYCRTSCRIPT=${HOME}/.gpp/certs/gen_client_keycrt.sh
CUR_DIR=$( dirname -- "$0"; )
KEYPEM=$CUR_DIR/client_key.pem
PUBPEM=$CUR_DIR/client_pubkey.pem
CRTPEM=$CUR_DIR/client_crt.pem
MSGTXT=${CUR_DIR}/msg.txt
MSGSIG=${CUR_DIR}/msg.sig
GENKEYCRTSCRIPT=${CUR_DIR}/gen_client_keycrt.sh

echo -e '\n'check integrity of ${KEYPEM}: 
# ${_openssl} rsa -in ${KEYPEM} -passin pass:111111 -check -noout
# ${_openssl} rsa -in ${KEYPEM} -check -noout
${_openssl} rsa -in ${KEYPEM} -check -noout | grep -q 'RSA key ok'
if [ $? -ne 0 ]
then
   echo "the integrity of "${KEYPEM}" is broken"
   # mail -s "$_sub" -r "$_from" "$_to" <<< "Warning: The certificate ($CACRTPEM) will expire soon on $HOSTNAME [$(date)]"
   # See https://www.cyberciti.biz/mobile-devices/android/how-to-push-send-message-to-ios-and-android-from-linux-cli/ #
   # source ~/bin/cli_app.sh
   # push_to_mobile "$0" "$_sub. See $_to email for detailed log. -- $HOSTNAME " >/dev/null

   # bash ${GENKEYCRTSCRIPT}
else
   echo -e "RSA key ok"   
fi

echo -e '\n'use private ${KEYPEM} to sign ${MSGTXT}: 
# ${_openssl} dgst -sha256 -sign ${KEYPEM} -passin pass:111111 -out msg.sig msg.txt
${_openssl} dgst -sha256 -sign ${KEYPEM} -out ${MSGSIG} ${MSGTXT}

echo -e '\n'get public key from ${CRTPEM}: 
${_openssl} x509 -in ${CRTPEM} -pubkey -out ${PUBPEM}

echo -e '\n'use public key in ${CRTPEM} to verify signature of ${MSGTXT}: 
# ${_openssl} dgst -sha256 -verify ${PUBPEM} -signature msg.sig msg.txt
${_openssl} dgst -sha256 -verify ${PUBPEM} -signature ${MSGSIG} ${MSGTXT}
${_openssl} dgst -sha256 -verify ${PUBPEM} -signature ${MSGSIG} ${MSGTXT} | grep -q 'Verified OK'
if [ $? -ne 0 ]
then
   echo ${KEYPEM}" is not matched with "${CRTPEM}
   # mail -s "$_sub" -r "$_from" "$_to" <<< "Warning: The certificate ($CACRTPEM) will expire soon on $HOSTNAME [$(date)]"
   # See https://www.cyberciti.biz/mobile-devices/android/how-to-push-send-message-to-ios-and-android-from-linux-cli/ #
   # source ~/bin/cli_app.sh
   # push_to_mobile "$0" "$_sub. See $_to email for detailed log. -- $HOSTNAME " >/dev/null

   # bash ${GENKEYCRTSCRIPT}
fi
rm -f ${PUBPEM}
