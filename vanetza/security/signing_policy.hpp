#ifndef C234BFC2_5BE1_49B6_90C3_0DFD7690BAB5
#define C234BFC2_5BE1_49B6_90C3_0DFD7690BAB5

#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>

namespace vanetza
{
namespace security
{

class SigningPolicy
{
public:
    virtual ~SigningPolicy() = default;
};

class DefaultSigningPolicy : public SigningPolicy
{
public:
    DefaultSigningPolicy(const Runtime&, PositionProvider&);
};

} // namespace security
} // namespace vanetza

#endif /* C234BFC2_5BE1_49B6_90C3_0DFD7690BAB5 */
