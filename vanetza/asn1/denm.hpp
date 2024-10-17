#ifndef DENM_HPP_XGC8NRDI
#define DENM_HPP_XGC8NRDI

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/DENM.h>
#include <vanetza/asn1/its/r2/DENM.h>

namespace vanetza
{
namespace asn1
{

namespace r1
{

class Denm : public asn1c_per_wrapper<DENM_t>
{
public:
    using wrapper = asn1c_per_wrapper<DENM_t>;
    Denm() : wrapper(asn_DEF_DENM) {}
};

} // namespace r1

namespace r2
{

class Denm : public asn1c_per_wrapper<Vanetza_ITS2_DENM_t>
{
public:
    using wrapper = asn1c_per_wrapper<Vanetza_ITS2_DENM_t>;
    Denm() : wrapper(asn_DEF_Vanetza_ITS2_DENM) {}
};

} // namespace r2

// alias for backward compatibility
using Denm = r1::Denm;

} // namespace asn1
} // namespace vanetza

#endif /* DENM_HPP_XGC8NRDI */
