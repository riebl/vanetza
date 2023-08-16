#ifndef C87A4E64_A531_404E_BF54_D4A2A6004781
#define C87A4E64_A531_404E_BF54_D4A2A6004781

#include <vanetza/security/hashed_id.hpp>
#include <memory>

namespace vanetza
{
namespace security
{

class Certificate
{
public:
    virtual ~Certificate() = default;
    virtual std::unique_ptr<Certificate> clone() const = 0;
    virtual bool is_root_ca() const = 0;
};

HashedId8 calculate_hash(const Certificate& cert);

} // namespace security
} // namespace vanetza

#endif /* C87A4E64_A531_404E_BF54_D4A2A6004781 */
