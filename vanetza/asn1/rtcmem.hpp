#ifndef RTCMEM_HPP_XAA1CDFFI
#define RTCMEM_HPP_XAA1CDFFI

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/RTCMEM.h>

namespace vanetza
{
namespace asn1
{

	class Rtcmem : public asn1c_per_wrapper<RTCMEM_t>
	{
	public:
		using wrapper = asn1c_per_wrapper<RTCMEM_t>;
		Rtcmem() : wrapper(asn_DEF_RTCMEM) {}
	};

} // namespace asn1
} // namespace vanetza

#endif //RTCMEM_HPP_XAA1CDFFI