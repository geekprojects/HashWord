#!/bin/bash

TESTDB=test.db
TESTUSER=testuser
MASTERPW1=test1234
MASTERPW2='m0RES3CUrE?'
DOMAIN1_NAME=example.com
DOMAIN1_PW1=3xampl3
DOMAIN1_PW2=Ch4ng3d

DOMAIN1_USER1=anotherUser
DOMAIN1_USER1_PW1=Another

DOMAIN2_NAME=thing.co.uk
DOMAIN2_PW1='! !'

DOMAIN3_NAME=generate.example.com

function savepassword()
{
    domain=$1
    domainuser=$2
    password=$3
    echo -e "${MASTERPW}\n${password}" | ./hashword --database ${TESTDB} --user ${TESTUSER} -s save "${domain}" "${domainuser}"
}

function generatepassword()
{
    domain=$1
    domainuser=$2

    results=`echo "${MASTERPW}" | ./hashword --database ${TESTDB} --user ${TESTUSER} -s generate $domain ${domainuser}|tr '\n' ':'`
    echo $results
}

function getpassword()
{
    domain=$1
    user=$2

    results=`echo "${MASTERPW}" | ./hashword --database ${TESTDB} --user ${TESTUSER} -s get $domain ${user}|tr '\n' ':'`
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

function changemasterpassword()
{
    original=$1
    new=$2

    echo -e "${original}\n${new}" | ./hashword --database ${TESTDB} --user ${TESTUSER} -s change
}


rm -f $TESTDB

export MASTERPW=$MASTERPW1

echo $MASTERPW | ./hashword --database ${TESTDB} --user ${TESTUSER} -s init

echo "Test: Domain 1: Set entry password"
savepassword $DOMAIN1_NAME '' $DOMAIN1_PW1
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW1

echo "Test: Domain 1: Change entry password"
savepassword $DOMAIN1_NAME '' $DOMAIN1_PW2
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW2

echo "Test: Domain 1: Set entry password, another user"
savepassword "$DOMAIN1_NAME" ${DOMAIN1_USER} ${DOMAIN1_USER1_PW1}
verifypassword "$DOMAIN1_NAME" ${DOMAIN1_USER} ${DOMAIN1_USER1_PW1}

echo "Test: Domain 2: Set another password"
savepassword $DOMAIN2_NAME '' ${DOMAIN2_PW1}
verifypassword $DOMAIN2_NAME '' ${DOMAIN2_PW1}

echo "Test: Domain 1: Verify original password"
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW2

echo "Test: Domain 3: Generate new password"
newpassword=`generatepassword $DOMAIN3_NAME`
verifypassword "$DOMAIN3_NAME" '' ${newpassword}

echo "Test: Change master password"
changemasterpassword $MASTERPW1 $MASTERPW2
export MASTERPW=$MASTERPW2

echo "Test: Domain 1 Verify original password"
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW2

echo "PASS!"

