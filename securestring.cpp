
#include <stdio.h>
#include <string.h>

#include "securestring.h"
#include "cryptoutils.h"

SecureString::SecureString()
{
    init(32);
}

SecureString::SecureString(const SecureString& str)
{
    m_bufferLength = str.m_bufferLength;
    init(m_bufferLength);

    m_stringLength = str.m_stringLength;
    memcpy(m_buffer, str.m_buffer, m_stringLength);
}

SecureString::SecureString(size_t bufferLength)
{
    init(bufferLength);
}

SecureString::SecureString(const char* str)
{
    size_t len = strlen(str);

    init(str, len);
}

SecureString::SecureString(const char* str, size_t length)
{
    init(str, length);
}

SecureString::SecureString(std::string str)
{
    init(str.c_str(), str.length());
}

SecureString::~SecureString()
{
    secureFree();
}

void SecureString::init(size_t bufferLength)
{
#ifdef DEBUG_SECURE_STRING
    printf("SecureString::init: Creating buffer with length=%lu\n", bufferLength);
#endif
    m_bufferLength = bufferLength * 2;

    if (m_bufferLength < 10)
    {
        m_bufferLength = 10;
    }

    m_buffer = new char[m_bufferLength];
    memset(m_buffer, 0, m_bufferLength);

    m_stringLength = 0;
}

void SecureString::init(const char* str, size_t length)
{
    init(length * 2);

    m_stringLength = length;

    memcpy(m_buffer, str, m_stringLength);
    m_buffer[m_stringLength] = 0;
}

void SecureString::expand(size_t min)
{
    size_t newLength = m_bufferLength;
    if (min > m_bufferLength)
    {
        newLength += min;
    }
    else
    {
        newLength += m_bufferLength;
    }

#ifdef DEBUG_SECURE_STRING
    printf("SecureString::expand: Expanding buffer %lu -> %lu\n", m_bufferLength, newLength);
#endif

    char* newBuffer = new char[newLength];
    memcpy(newBuffer, m_buffer, m_stringLength);
    newBuffer[m_stringLength] = 0;

    secureFree();

    m_bufferLength = newLength;
    m_buffer = newBuffer;
}

void SecureString::secureFree()
{
#ifdef DEBUG_SECURE_STRING
    printf("SecureString::secureFree: Freeing buffer with length=%lu, string length=%lu\n", m_bufferLength, m_stringLength);
#endif
    if (m_buffer != NULL)
    {
        CryptoUtils::shred(m_buffer, m_bufferLength);
        delete[] m_buffer;
    }
}

SecureString& SecureString::operator =(const SecureString& rhs)
{
    m_bufferLength = rhs.m_bufferLength;
    m_stringLength = rhs.m_stringLength;
    m_buffer = new char[m_bufferLength];
    memset(m_buffer, 0, m_bufferLength);
    memcpy(m_buffer, rhs.m_buffer, m_stringLength);
    return *this;
}

SecureString SecureString::operator +=(char rhs)
{
    if (m_bufferLength <= m_stringLength + 1)
    {
        expand(1);
    }

    m_buffer[m_stringLength] = rhs;
    m_stringLength++;
    m_buffer[m_stringLength] = 0;

    return *this;
}

SecureString SecureString::operator +=(const char* rhs)
{
    int rhsLen = strlen(rhs);

    if (m_bufferLength <= m_stringLength + rhsLen)
    {
        expand(rhsLen);
    }

    strncpy(m_buffer + m_stringLength, rhs, rhsLen);
    m_stringLength += rhsLen;
    m_buffer[m_stringLength] = 0;

    return *this;
}

SecureString SecureString::operator +=(SecureString& rhs)
{
    if (m_bufferLength <= m_stringLength + rhs.m_stringLength)
    {
        expand(rhs.m_stringLength);
    }

    strncpy(m_buffer + m_stringLength, rhs.m_buffer, rhs.m_stringLength);
    m_stringLength += rhs.m_stringLength;
    m_buffer[m_stringLength] = 0;

    return *this;
}

SecureString SecureString::operator +(char rhs)
{
    size_t totalLen = length() + 1;
    SecureString newString(totalLen * 2);
    newString.m_stringLength = totalLen;

    memcpy(newString.m_buffer, m_buffer, length());
    newString.m_buffer[totalLen - 1] = rhs;
    newString.m_buffer[totalLen] = 0;

    return newString;
}


SecureString SecureString::operator +(const char* rhs)
{
    size_t rhsLen = strlen(rhs);

    size_t totalLen = length() + rhsLen;
    SecureString newString(totalLen * 2);
    newString.m_stringLength = totalLen;

    memcpy(newString.m_buffer, m_buffer, length());
    memcpy(newString.m_buffer + length(), rhs, rhsLen);
    newString.m_buffer[totalLen] = 0;

    return newString;
}

SecureString SecureString::operator +(const SecureString& rhs)
{
    size_t totalLen = length() + rhs.length();
    SecureString newString(totalLen);
    newString.m_stringLength = totalLen;

    memcpy(newString.m_buffer, m_buffer, length());
    memcpy(newString.m_buffer + length(), rhs.m_buffer, rhs.length());
    m_buffer[totalLen] = 0;

    return newString;
}

bool SecureString::operator !=(const SecureString& rhs)
{
    if (m_stringLength != rhs.m_stringLength)
    {
        return true;
    }

    unsigned int i;
    for (i = 0; i < m_stringLength; i++)
    {
        if (m_buffer[i] != rhs.m_buffer[i])
        {
            return true;
        }
    }
    return false;
}

std::string SecureString::string() const
{
    return std::string(m_buffer, m_stringLength);
}

void SecureString::clear()
{
    m_stringLength = 0;
    CryptoUtils::shred(m_buffer, m_bufferLength);
}

#ifdef __TEST_SECURE_STRING

SecureString testfunc(SecureString a)
{
    return a + "Yeah!";
}

int main(int argc, char** argv)
{
    SecureString hello = SecureString("Hello"); 
    SecureString world = SecureString("World!"); 

    SecureString str = hello + " " + world;

    SecureString suffix = "@?";
    SecureString appendage;

    std::string cppstring = "~~";

    int i;
    for (i = 0; i < 5; i++)
    {
        SecureString securecppstring = SecureString(cppstring);
        SecureString suffix2 = testfunc(suffix);
        appendage += "Weeee";
        appendage += '!';
        appendage += securecppstring;
        appendage += suffix2;
    }
    
    str += appendage;

    printf("%s\n", str.c_str());

    std::string cppstr = str.string();
    printf("%s\n", cppstr.c_str());

    str.clear();
    str += "The End";

    printf("%s\n", str.c_str());

    if (str != SecureString("Hello!"))
    {
        printf("!= is correct!\n");
    }
    else
    {
        printf("!= is wrong!\n");
    }

    if (SecureString("Hello?") != SecureString("Hello!"))
    {
        printf("!= is correct!\n");
    }
    else
    {
        printf("!= is wrong!\n");
    }

    return 0;
}
#endif

