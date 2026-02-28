#include <vanetza/asn1/security/EccP256CurvePoint.h>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <boost/variant/static_visitor.hpp>
#include <algorithm>
#include <cstring>

namespace vanetza
{
namespace security
{
namespace v3
{

HashedId8 convert(const Vanetza_Security_HashedId8_t& in)
{
    HashedId8 out;
    std::memcpy(out.data(), in.buf, std::min(out.size(), in.size));
    return out;
}

void assign(OCTET_STRING_t* dst, const ByteBuffer& src)
{
    OCTET_STRING_fromBuf(dst, reinterpret_cast<const char*>(src.data()), src.size());
}

asn1::EccP256CurvePoint to_asn1(const EccPoint& point)
{
    struct visitor : public boost::static_visitor<asn1::EccP256CurvePoint>
    {
        asn1::EccP256CurvePoint operator()(const X_Coordinate_Only& x_only) const
        {
            asn1::EccP256CurvePoint result = {};
            result.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
            assign(&result.choice.x_only, x_only.x);
            return result;
        }

        asn1::EccP256CurvePoint operator()(const Compressed_Lsb_Y_0& y0) const
        {
            asn1::EccP256CurvePoint result = {};
            result.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
            assign(&result.choice.compressed_y_0, y0.x);
            return result;
        }

        asn1::EccP256CurvePoint operator()(const Compressed_Lsb_Y_1& y1) const
        {
            asn1::EccP256CurvePoint result = {};
            result.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1;
            assign(&result.choice.compressed_y_1, y1.x);
            return result;
        }

        asn1::EccP256CurvePoint operator()(const Uncompressed& unc) const
        {
            asn1::EccP256CurvePoint result = {};
            result.present = Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256;
            assign(&result.choice.uncompressedP256.x, unc.x);
            assign(&result.choice.uncompressedP256.y, unc.y);
            return result;
        }
    };

    return boost::apply_visitor(visitor(), point);
}

} // namespace v3

HashedId8 create_hashed_id8(const Vanetza_Security_HashedId8_t& in)
{
    HashedId8 out;
    std::memcpy(out.data(), in.buf, std::min(out.size(), in.size));
    return out;    
}

HashedId3 create_hashed_id3(const Vanetza_Security_HashedId3_t& in)
{
    HashedId3 out;
    std::memcpy(out.data(), in.buf, std::min(out.size(), in.size));
    return out;
}

} // namespace security
} // namespace vanetza
