#! /bin/sh
# Purpose: Alert sysadmin/developer about the cert expiry date in advance
# Author:   under license
# -------------------------------------------------------------------------------


_openssl="openssl"


# CACRTPEM=$HOME/.gpp/certs/ca_crt.pem
# REGENCRTSCRIPT=${HOME}/gen_ca_crt.sh
CUR_DIR=$( dirname -- "$0"; )
CACRTPEM=$CUR_DIR/ca_crt.pem
REGENCRTSCRIPT=${CUR_DIR}/gen_ca_crt.sh

# 7 days in seconds 
DAYS="604800" 

# Email settings 
_sub=$CACRTPEM" will expire within $DAYS seconds (7 days)"
# _sub="${CACRTPEM} will expire within $DAYS seconds (7 days)"
_from="system-account@your-dommain"
_to="sysadmin@your-domain"

echo -e '\n'get date of $CACRTPEM: 
openssl x509 -in $CACRTPEM -noout -dates

echo -e '\n'check expiry of $CACRTPEM: 
$_openssl x509 -enddate -noout -in "$CACRTPEM" -checkend "$DAYS"
$_openssl x509 -enddate -noout -in "$CACRTPEM" -checkend "$DAYS" | grep -q 'Certificate will expire'
# If will expire, regenerate key and certifcate 
# // , and send email
if [ $? -eq 0 ]
then
   echo "${_sub}"
   # mail -s "$_sub" -r "$_from" "$_to" <<< "Warning: The certificate ($CACRTPEM) will expire soon on $HOSTNAME [$(date)]"
   # See https://www.cyberciti.biz/mobile-devices/android/how-to-push-send-message-to-ios-and-android-from-linux-cli/ #
   # source ~/bin/cli_app.sh
   # push_to_mobile "$0" "$_sub. See $_to email for detailed log. -- $HOSTNAME " >/dev/null

   # bash ${REGENCRTSCRIPT}
fi
