#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/public_key.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace security
{

class EccPointVisitor : public boost::static_visitor<ByteBuffer>
{
public:
    template<typename T>
    ByteBuffer operator()(const T& point)
    {
        return point.x;
    }
};

ByteBuffer convert_for_signing(const EccPoint& ecc_point)
{
    EccPointVisitor visit;
    return boost::apply_visitor(visit, ecc_point);
}

class EccPointLengthVisitor : public boost::static_visitor<std::size_t>
{
public:
    std::size_t operator()(const X_Coordinate_Only& x_only) const
    {
        return x_only.x.size();
    }

    std::size_t operator()(const Compressed_Lsb_Y_0& y0) const
    {
        return y0.x.size();
    }

    std::size_t operator()(const Compressed_Lsb_Y_1& y1) const
    {
        return y1.x.size();
    }

    std::size_t operator()(const Uncompressed& unc) const
    {
        return unc.x.size() + unc.y.size();
    }
};

std::size_t get_length(const EccPoint& point)
{
    EccPointLengthVisitor visitor;
    return boost::apply_visitor(visitor, point);
}

EccPoint compress_public_key(const PublicKey& public_key)
{
    switch (public_key.compression)
    {
        case KeyCompression::NoCompression:
            if (!public_key.y.empty() && public_key.y.back() & 0x01) {
                return Compressed_Lsb_Y_1 {public_key.x };
            } else {
                return Compressed_Lsb_Y_0 {public_key.x };
            }
        case KeyCompression::Y0:
            return Compressed_Lsb_Y_0 {public_key.x };
        case KeyCompression::Y1:
            return Compressed_Lsb_Y_1 {public_key.x };
        default:
            return Compressed_Lsb_Y_0 {};
    }
}

EccPoint compress_public_key(const ecdsa256::PublicKey& public_key)
{
    if (!public_key.y.empty() && public_key.y.back() & 0x01) {
        return Compressed_Lsb_Y_1 { ByteBuffer { public_key.x.begin(), public_key.x.end() } };
    } else {
        return Compressed_Lsb_Y_0 { ByteBuffer { public_key.x.begin(), public_key.x.end() } };
    }
}

} // namespace security
} // namespace vanetza
