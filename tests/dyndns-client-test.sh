#!/bin/sh

. ./.env

password=$1

#	--password=${PASSWORD_CT} \
#	--user="${USERNAME}" \

wget -O - \
	--no-verbose \
	--auth-no-challenge \
	--no-check-certificate \
	https://${HOST}/nic/update?username=${USERNAME}\&password="${PASSWORD_CT}"\&hostname=dns-test.dyn.bgwlan.nl\&myip=127.0.0.1\&updatetype=aws
