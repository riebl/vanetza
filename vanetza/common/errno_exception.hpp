#ifndef ERRNO_EXCEPTION_HPP_ULYZ87TW
#define ERRNO_EXCEPTION_HPP_ULYZ87TW

#include <cstring>
#include <stdexcept>

class ErrnoException : public std::runtime_error
{
public:
    ErrnoException(int number) :
        std::runtime_error(strerror(number)), mErrno(number) {}
    int number() const { return mErrno; }

private:
    int mErrno;
};

#endif /* ERRNO_EXCEPTION_HPP_ULYZ87TW */

