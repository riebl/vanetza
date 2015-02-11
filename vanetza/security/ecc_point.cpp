#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/public_key.hpp>

namespace vanetza {
namespace security {

size_t get_size(const EccPoint& point) {
    size_t size = 0;
    EccPointType type = get_type(point);
    switch (type) {
    case EccPointType::X_Coordinate_Only: {
        X_Coordinate_Only coord;
        coord = boost::get<X_Coordinate_Only>(point);
        size += coord.x.size();
        size += sizeof(type);
        break;
    }
    case EccPointType::Compressed_Lsb_Y_0: {
        Compressed_Lsb_Y_0 coord;
        coord = boost::get<Compressed_Lsb_Y_0>(point);
        size += coord.x.size();
        size += sizeof(type);
        break;
    }
    case EccPointType::Compressed_Lsb_Y_1: {
        Compressed_Lsb_Y_1 coord;
        coord = boost::get<Compressed_Lsb_Y_1>(point);
        size += coord.x.size();
        size += sizeof(type);
        break;
    }
    case EccPointType::Uncompressed: {
        Uncompressed coord;
        coord = boost::get<Uncompressed>(point);
        size += coord.x.size();
        size += coord.y.size();
        size += sizeof(type);
        break;
    }
    }
    return size;
}

EccPointType get_type(const EccPoint& point) {
    struct ecc_point_visitor: public boost::static_visitor<> {
        void operator()(X_Coordinate_Only coord) {
            type = EccPointType::X_Coordinate_Only;
        }
        void operator()(Compressed_Lsb_Y_0 coord) {
            type = EccPointType::Compressed_Lsb_Y_0;
        }
        void operator()(Compressed_Lsb_Y_1 coord) {
            type = EccPointType::Compressed_Lsb_Y_1;
        }
        void operator()(Uncompressed coord) {
            type = EccPointType::Uncompressed;
        }
        EccPointType type;
    };

    ecc_point_visitor visit;
    boost::apply_visitor(visit, point);
    return visit.type;
}

void serialize(OutputArchive& ar, const EccPoint& point) {
    struct ecc_point_visitor: public boost::static_visitor<> {
        ecc_point_visitor(OutputArchive& ar) :
                m_archive(ar){
        }
        void operator()(X_Coordinate_Only coord) {
            for (auto byte : coord.x) {
                m_archive << byte;
            }
        }
        void operator()(Compressed_Lsb_Y_0 coord) {
            for (auto byte : coord.x) {
                m_archive << byte;
            }
        }
        void operator()(Compressed_Lsb_Y_1 coord) {
            for (auto byte : coord.x) {
                m_archive << byte;
            }
        }
        void operator()(Uncompressed coord) {
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
    ar << type;
    ecc_point_visitor visit(ar);
    boost::apply_visitor(visit, point);
}

void deserialize(InputArchive& ar, EccPoint& point, PublicKeyAlgorithm algo) {
    size_t size = field_size(algo);
    uint8_t elem;
    EccPointType type;
    ar >> type;
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

