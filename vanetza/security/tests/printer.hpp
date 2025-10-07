#pragma once
#include <boost/optional/optional_io.hpp>
#include <vanetza/security/decap_service.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <ostream>

namespace vanetza
{
namespace security
{

void PrintTo(const DecapReport& report, std::ostream* out)
{
    struct Printer : boost::static_visitor<>
    {
        Printer(std::ostream* out) : out(out) {}

        void operator()(const VerificationReport& report) const
        {
            *out << "DecapReport(VerificationReport(" << static_cast<int>(report) << "))";
        }

        void operator()(const boost::blank&) const
        {
            *out << "DecapReport(None)";
        }

        std::ostream* out;
    };
    boost::apply_visitor(Printer(out), report);
}

} // namespace security
} // namespace vanetza

namespace std {

/* HashedId3 and HashedId8 are mere type aliases of std::array<> */

std::ostream& operator<<(std::ostream& os, const vanetza::security::HashedId3& id)
{
    os << vanetza::security::to_string(id);
    return os;
}

std::ostream& operator<<(std::ostream& os, const vanetza::security::HashedId8& id)
{
    os << vanetza::security::to_string(id);
    return os;
}

} // namespace std
