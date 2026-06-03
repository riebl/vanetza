#pragma once

#include <stdexcept>
#include <string>

namespace vanetza
{
namespace pki
{

class DecodingFailure : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};

class VerificationFailure : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};

class UsageError : public std::runtime_error
{
public:
    UsageError(const std::string& problem) : std::runtime_error(problem) {}
    UsageError(const std::string& problem, const std::string& remedy) :
        std::runtime_error(problem), m_remedy(remedy)
    {
    }

    const std::string& remedy() const { return m_remedy; }

private:
    std::string m_remedy;
};

} // namespace pki
} // namespace vanetza
