#ifndef DESERIALIZATION_ERROR_HPP_MEINSOIS
#define DESERIALIZATION_ERROR_HPP_MEINSOIS

#include <stdexcept>

namespace vanetza
{
namespace security
{

class deserialization_error : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

} // namespace security
} // namespace vanetza

#endif /* DESERIALIZATION_ERROR_HPP_MEINSOIS */
