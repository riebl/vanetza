#ifndef CFE4DC34_AD31_47E8_9EB2_1B98C6FB0887
#define CFE4DC34_AD31_47E8_9EB2_1B98C6FB0887

#include <vanetza/common/byte_buffer.hpp>
#include <boost/variant/variant.hpp>

namespace vanetza
{
namespace security
{

/// X_Coordinate_Only specified in TS 103 097 v1.2.1 in section 4.2.5
struct X_Coordinate_Only
{
    ByteBuffer x;
};

/// Compressed_Lsb_Y_0 specified in TS 103 097 v1.2.1 in section 4.2.5
struct Compressed_Lsb_Y_0
{
    ByteBuffer x;
};

/// Compressed_Lsb_Y_1 specified in TS 103 097 v1.2.1 in section 4.2.5
struct Compressed_Lsb_Y_1
{
    ByteBuffer x;
};

/// Uncompressed specified in TS 103 097 v1.2.1 in section 4.2.5
struct Uncompressed
{
    ByteBuffer x;
    ByteBuffer y;
};

/// EccPoint specified in TS 103 097 v1.2.1 in section 4.2.5
using EccPoint = boost::variant<
    X_Coordinate_Only,
    Compressed_Lsb_Y_0,
    Compressed_Lsb_Y_1,
    Uncompressed
>;

/**
 * \brief calculate byte length of ECC point structure
 * \param ecc_point 
 * \return length in bytes
 */
std::size_t get_length(const EccPoint& ecc_point);

/**
 * \brief Convert EccPoint for signature calculation
 * Uses ecc_point.x as relevant field for signatures.
 *
 * \param ecc_point
 * \return binary representation of ECC point
 */
ByteBuffer convert_for_signing(const EccPoint& ecc_point);

} // namespace security
} // namespace vanetza

#endif /* CFE4DC34_AD31_47E8_9EB2_1B98C6FB0887 */
