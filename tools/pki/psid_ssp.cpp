#include "psid_ssp.hpp"
#include <boost/algorithm/hex.hpp>
#include <charconv>

namespace vanetza
{
namespace pki
{

bool lexical_cast(const std::string& input, PsidSsp& permission)
{
    // split into the decimal PSID and the optional ':'-separated hex SSP.
    const std::size_t colon = input.find(':');
    const char* first = input.data();
    const char* last = input.data() + (colon == std::string::npos ? input.size() : colon);

    decltype(permission.psid) psid = 0;
    auto [ptr, ec] = std::from_chars(first, last, psid);
    if (ec != std::errc {} || ptr != last) {
        // empty, contains a non-digit, or out of range
        return false;
    }

    // found SSP part
    if (colon != std::string::npos) {
        try {
            ByteBuffer ssp;
            boost::algorithm::unhex(input.begin() + colon + 1, input.end(), std::back_inserter(ssp));
            permission.ssp = std::move(ssp);
        } catch (boost::algorithm::hex_decode_error&) {
            return false;
        }
    }

    permission.psid = psid;
    return true;
}

} // namespace pki
} // namespace vanetza
