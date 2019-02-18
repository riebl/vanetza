#include <boost/variant.hpp>
#include <vanetza/security/ecc_point.hpp>

namespace vanetza
{
namespace security
{

struct EccPointDecompressionVisitor : public boost::static_visitor<Uncompressed> {
    Uncompressed operator()(X_Coordinate_Only p) {
        // Without the additional bit of the y coordinate, we cannot restore y.
        Uncompressed u {p.x};
        return u;
    }

    Uncompressed operator()(Compressed_Lsb_Y_0 p) {
        return decompress(p.x, EccPointType::Compressed_Lsb_Y_0);
    }

    Uncompressed operator()(Compressed_Lsb_Y_1 p) {
        return decompress(p.x, EccPointType::Compressed_Lsb_Y_1);
    }

    Uncompressed operator()(Uncompressed p) {
        return Uncompressed(p);
    }

    virtual Uncompressed decompress(ByteBuffer x, EccPointType type) {
        throw std::logic_error("Decompression of EccPoints not supported!");
    }
};

} // ns security
} // ns vanetza
