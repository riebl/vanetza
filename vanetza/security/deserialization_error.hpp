#ifndef DESERIALIZATION_ERROR_HPP_MEINSOIS
#define DESERIALIZATION_ERROR_HPP_MEINSOIS

#include <stdexcept>

namespace vanetza
{
namespace security
{

struct deserialization_error : public std::runtime_error
{
public:
    deserialization_error(const std::string msg) : std::runtime_error(msg)
    {
    }
};

} // namespace security
} // namespace vanetza

#endif /* DESERIALIZATION_ERROR_HPP_MEINSOIS */
