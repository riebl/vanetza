#ifndef RANGING_SAM_DATA_HPP_WXYNEKFN
#define RANGING_SAM_DATA_HPP_WXYNEKFN

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/ITSRangingSAMAppData.h>

namespace vanetza
{
namespace asn1
{

namespace r1
{

// Ranging Service Application Data (ETSI EN 302 890-2 clause 7.3.2.2, Annex A.1).
// Its UPER encoding is carried in SAMapplicationData of a SAM ServiceInfoExt.
class RangingSamAppData : public asn1c_per_wrapper<ITSRangingSAMAppData_t>
{
public:
    using wrapper = asn1c_per_wrapper<ITSRangingSAMAppData_t>;
    RangingSamAppData() : wrapper(asn_DEF_ITSRangingSAMAppData) {}
};

} // namespace r1

using RangingSamAppData = r1::RangingSamAppData;

} // namespace asn1
} // namespace vanetza

#endif /* RANGING_SAM_DATA_HPP_WXYNEKFN */
