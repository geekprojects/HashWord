#ifndef __HASHWORD_SECURE_STRING_H_
#define __HASHWORD_SECURE_STRING_H_

#include <string>

class SecureString
{
 private:
    char* m_buffer;
    size_t m_bufferLength;
    size_t m_stringLength;

    void init(const char* str, size_t stringLength);
    void init(size_t bufferLength);

    void expand(size_t min);

    void secureFree();

 public:
    SecureString();
    SecureString(const SecureString& str);
    SecureString(size_t bufferLength);
    SecureString(const char* str);
    SecureString(const char* str, size_t length);
    SecureString(std::string str);

    virtual ~SecureString();

    SecureString& operator=( const SecureString& other );

    SecureString operator +=(char rhs);
    SecureString operator +=(const char* rhs);
    SecureString operator +=(SecureString& rhs);

    SecureString operator +(char rhs);
    SecureString operator +(const char* rhs);
    SecureString operator +(const SecureString& rhs);

    char at(unsigned int idx);

    bool operator !=(const SecureString& rhs);

    size_t length() const { return m_stringLength; }
    const char* c_str() const { return m_buffer; }
    std::string string() const;

    void clear();
};

#endif
