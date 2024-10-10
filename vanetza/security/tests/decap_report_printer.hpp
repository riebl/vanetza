#ifndef DEA0116A_C521_407B_B2E3_B4C272C53C4C
#define DEA0116A_C521_407B_B2E3_B4C272C53C4C

#include <vanetza/security/decap_service.hpp>
#include <iostream>

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

#endif /* DEA0116A_C521_407B_B2E3_B4C272C53C4C */
