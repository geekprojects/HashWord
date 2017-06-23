#!/bin/bash

TESTDB1=test.db
TESTDB2=test_copy.db
TESTUSER=testuser
MASTERPW1=test1234
MASTERPW2='m0RES3CUrE?'
DOMAIN1_NAME=example.com
DOMAIN1_PW1=3xampl3
DOMAIN1_PW2=Ch4ng3d
DOMAIN1_PW3=lo7sofchang3s

DOMAIN1_USER1=anotherUser
DOMAIN1_USER1_PW1=Another

DOMAIN2_NAME=thing.co.uk
DOMAIN2_PW1='! !'

DOMAIN3_NAME=generate.example.com
DOMAIN4_NAME=synctest.example.com
DOMAIN5_NAME=syncnewtest.example.com

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

    #results=`echo "${MASTERPW}" | ./hashword --database ${TESTDB} --user ${TESTUSER} -s gen $domain ${domainuser}|tr '\n' ':'|cut -d':'`
    results=`echo "${MASTERPW}" | ./hashword --database ${TESTDB} --user ${TESTUSER} -s gen $domain ${domainuser}`
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

    if [ -z "${user}" ]
    then
        formatted=${domain}
    else
        formatted=${user}@${domain}
    fi

    got=`getpassword $domain $user`

    if [[ "${got}" != "${expected}" ]]
    then
        echo "FAIL: ${formatted}: Password is incorrect: Got=$got Expected=$expected"
        exit 255
    else
        echo "PASS: ${formatted}: Password is correct"
    fi
}

function changemasterpassword()
{
    original=$1
    new=$2

    echo -e "${original}\n${new}" | ./hashword --database ${TESTDB} --user ${TESTUSER} -s change
}

function syncdbs()
{
    target=$1

    echo -e "${MASTERPW}" | ./hashword --database ${TESTDB} --user ${TESTUSER} -s sync ${target}
}



rm -f $TESTDB1 $TESTDB2

export TESTDB=$TESTDB1
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


# Sync tests
cp $TESTDB1 $TESTDB2

echo "Test: Sync Test: Domain 1: Change entry password"
savepassword $DOMAIN1_NAME '' $DOMAIN1_PW3
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW3

echo "Test: Sync Test: Generate new password"
synctestpassword=`generatepassword $DOMAIN4_NAME`
verifypassword "$DOMAIN4_NAME" '' ${synctestpassword}

syncdbs $TESTDB2

export TESTDB=$TESTDB2

echo "Test: Verify synced password"
verifypassword $DOMAIN4_NAME '' $synctestpassword

echo "Test: Sync Test: Change password in other DB"
synctestpassword2=`generatepassword $DOMAIN4_NAME`
verifypassword "$DOMAIN4_NAME" '' ${synctestpassword2}

echo "Test: Sync Test: Add entry in other DB"
synctestpassword3=`generatepassword $DOMAIN5_NAME`
verifypassword "$DOMAIN5_NAME" '' ${synctestpassword3}

export TESTDB=$TESTDB1

syncdbs $TESTDB2

echo "Test: Sync Test: Verifying changes in other DB have been syncd back"
verifypassword "$DOMAIN4_NAME" '' ${synctestpassword2}
verifypassword "$DOMAIN5_NAME" '' ${synctestpassword3}

# And finally triple check we haven't lost our first entry!
echo "Test: Verify original passwords"
verifypassword $DOMAIN1_NAME '' $DOMAIN1_PW3
verifypassword $DOMAIN2_NAME '' ${DOMAIN2_PW1}

echo "PASS!"

