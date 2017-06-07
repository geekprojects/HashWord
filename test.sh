#!/bin/bash

TESTDB=test.db
MASTERPW=test1234
DOMAIN1_NAME=example.com
DOMAIN1_PW1=3xampl3
DOMAIN1_PW2=Ch4ng3d

DOMAIN1_USER1=user@test.com
DOMAIN1_USER1_PW1=Another

DOMAIN2_NAME=thing.co.uk
DOMAIN2_PW1='! !'

function savepassword()
{
    domain=$1
    user=$2
    password=$3
    echo -e "${MASTERPW}\n${password}" | ./hashword --database ${TESTDB} -s savepassword "${domain}" "${user}"
}

function getpassword()
{
    domain=$1
    user=$2

    results=`echo "${MASTERPW}" | ./hashword --database ${TESTDB} -s getpassword $domain ${user}|tr '\n' ':'`
    results_pw=`echo $results|cut -f2 -d':'`
    echo $results_pw
}

function verifypassword()
{
    domain=$1
    user=$2
    expected=$3

    got=`getpassword $domain $user`

    if [[ "${got}" != "${expected}" ]]
    then
        echo "FAIL: Password is incorrect: Got=$got Expected=$expected"
        exit 255
    else
        echo "PASS: Password is correct"
    fi
}

rm -f $TESTDB

echo $MASTERPW | ./hashword --database ${TESTDB} -s init

echo "Test: Set entry password"
savepassword $DOMAIN1_NAME '' $DOMAIN1_PW1
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW1

echo "Test: Change entry password"
savepassword $DOMAIN1_NAME '' $DOMAIN1_PW2
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW2

echo "Test: Set entry password, another user"
savepassword "$DOMAIN1_NAME" "$DOMAIN1_USER" $DOMAIN1_USER1_PW1
verifypassword "$DOMAIN1_NAME" "$DOMAIN1_USER" ${DOMAIN1_USER1_PW1}

echo "Test: Set another password"
savepassword $DOMAIN2_NAME '' "$DOMAIN2_PW1"
verifypassword $DOMAIN2_NAME '' "$DOMAIN2_PW1"

echo "Test: Verify original password"
savepassword $DOMAIN1_NAME '' $DOMAIN1_PW2
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW2

echo "PASS!"

