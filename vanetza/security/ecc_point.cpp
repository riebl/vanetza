#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/public_key.hpp>

namespace vanetza
{
namespace security
{

size_t get_size(const EccPoint& point)
{
    size_t size = sizeof(EccPointType);
    struct ecc_point_visitor : public boost::static_visitor<size_t>
    {
        size_t operator()(X_Coordinate_Only coord)
        {
            return coord.x.size();
        }
        size_t operator()(Compressed_Lsb_Y_0 coord)
        {
            return coord.x.size();
        }
        size_t operator()(Compressed_Lsb_Y_1 coord)
        {
            return coord.x.size();
        }
        size_t operator()(Uncompressed coord)
        {
            return coord.x.size() + coord.y.size();
        }
    };

    ecc_point_visitor visit;
    boost::apply_visitor(visit, point);

    size += boost::apply_visitor(visit, point);
    return size;
}

EccPointType get_type(const EccPoint& point)
{
    struct ecc_point_visitor : public boost::static_visitor<EccPointType>
    {
        EccPointType operator()(X_Coordinate_Only coord)
        {
            return EccPointType::X_Coordinate_Only;
        }
        EccPointType operator()(Compressed_Lsb_Y_0 coord)
        {
            return EccPointType::Compressed_Lsb_Y_0;
        }
        EccPointType operator()(Compressed_Lsb_Y_1 coord)
        {
            return EccPointType::Compressed_Lsb_Y_1;
        }
        EccPointType operator()(Uncompressed coord)
        {
            return EccPointType::Uncompressed;
        }
    };

    ecc_point_visitor visit;
    return boost::apply_visitor(visit, point);
}

void serialize(OutputArchive& ar, const EccPoint& point)
{
    struct ecc_point_visitor : public boost::static_visitor<>
    {
        ecc_point_visitor(OutputArchive& ar) :
            m_archive(ar)
        {
        }
        void operator()(X_Coordinate_Only coord)
        {
            for (auto byte : coord.x) {
                m_archive << byte;
            }
        }
        void operator()(Compressed_Lsb_Y_0 coord)
        {
            for (auto byte : coord.x) {
                m_archive << byte;
            }
        }
        void operator()(Compressed_Lsb_Y_1 coord)
        {
            for (auto byte : coord.x) {
                m_archive << byte;
            }
        }
        void operator()(Uncompressed coord)
        {
            for (auto byte : coord.x) {
                m_archive << byte;
            }
            for (auto byte : coord.y) {
                m_archive << byte;
            }
        }
        OutputArchive& m_archive;
    };

    EccPointType type = get_type(point);
    serialize(ar, type);
    ecc_point_visitor visit(ar);
    boost::apply_visitor(visit, point);
}

void deserialize(InputArchive& ar, EccPoint& point, PublicKeyAlgorithm algo)
{
    size_t size = field_size(algo);
    uint8_t elem;
    EccPointType type;
    deserialize(ar, type);
    switch (type) {
        case EccPointType::X_Coordinate_Only: {
            X_Coordinate_Only coord;
            for (size_t c = 0; c < size; c++) {
                ar >> elem;
                coord.x.push_back(elem);
            }
            point = coord;
            break;
        }
        case EccPointType::Compressed_Lsb_Y_0: {
            Compressed_Lsb_Y_0 coord;
            for (size_t c = 0; c < size; c++) {
                ar >> elem;
                coord.x.push_back(elem);
            }
            point = coord;
            break;
        }
        case EccPointType::Compressed_Lsb_Y_1: {
            Compressed_Lsb_Y_1 coord;
            for (size_t c = 0; c < size; c++) {
                ar >> elem;
                coord.x.push_back(elem);
            }
            point = coord;
            break;
        }
        case EccPointType::Uncompressed: {
            Uncompressed coord;
            for (size_t c = 0; c < size; c++) {
                ar >> elem;
                coord.x.push_back(elem);
            }
            for (size_t c = 0; c < size; c++) {
                ar >> elem;
                coord.y.push_back(elem);
            }
            point = coord;
            break;
        }
        default:
            throw deserialization_error("Unknown EccPointType");
    }
}

} // namespace security
} // namespace vanetza

