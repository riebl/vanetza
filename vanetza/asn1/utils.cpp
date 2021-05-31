#include <vanetza/asn1/utils.hpp>


namespace vanetza
{
namespace asn1
{
void convert_bytebuffer_to_octet_string(OCTET_STRING_t* octet, const vanetza::ByteBuffer& buffer)
{
    OCTET_STRING_fromBuf(
        octet,
        reinterpret_cast<const char *>(buffer.data()),
        buffer.size()
    );
}

vanetza::security::EccPoint EccP256CurvePoint_to_EccPoint(const EccP256CurvePoint_t& curve_point){
    vanetza::security::EccPoint to_return;
    switch(curve_point.present){
        case EccP256CurvePoint_PR_x_only:
            to_return = vanetza::security::X_Coordinate_Only{
                .x=OCTET_STRING_to_ByteBuffer(curve_point.choice.x_only)
                };
            break;
	    case EccP256CurvePoint_PR_compressed_y_0:
            to_return = vanetza::security::Compressed_Lsb_Y_0{
                .x=OCTET_STRING_to_ByteBuffer(curve_point.choice.compressed_y_0)
                };
            break;
	    case EccP256CurvePoint_PR_compressed_y_1:
            to_return = vanetza::security::Compressed_Lsb_Y_1{
                .x=OCTET_STRING_to_ByteBuffer(curve_point.choice.compressed_y_1)
                };
            break;
	    case EccP256CurvePoint_PR_uncompressedP256:
            to_return = vanetza::security::Uncompressed{
                .x=OCTET_STRING_to_ByteBuffer(curve_point.choice.uncompressedP256.x),
                .y=OCTET_STRING_to_ByteBuffer(curve_point.choice.uncompressedP256.y)};
            break;
    }
    return to_return;
}

vanetza::security::GeographicRegion GeographicRegionAsn_to_GeographicRegion(const GeographicRegion_t& region){
    vanetza::security::GeographicRegion to_return = vanetza::security::NoneRegion();
    std::list<vanetza::security::RectangularRegion> to_return_list;
    vanetza::security::PolygonalRegion polygon;
    switch(region.present){
        case GeographicRegion_PR_circularRegion:
            to_return = vanetza::security::CircularRegion(
                TwoDLocationAsn_to_TwoDLocation(
                    region.choice.circularRegion.center
                ),
                geonet::distance_u16t::from_value(region.choice.circularRegion.radius)
            );
            break;
	    case GeographicRegion_PR_rectangularRegion:
            for (int i=0; i<region.choice.rectangularRegion.list.count; i++){
                    to_return_list.push_back(
                        vanetza::security::RectangularRegion{
                            .northwest = TwoDLocationAsn_to_TwoDLocation(
                                region.choice.rectangularRegion.list.array[i]->northWest
                            ),
                            .southeast = TwoDLocationAsn_to_TwoDLocation(
                                region.choice.rectangularRegion.list.array[i]->southEast)
                        }
                    );
            }
            to_return = to_return_list;
            break;
	    case GeographicRegion_PR_polygonalRegion:
            for (int i=0; i<region.choice.polygonalRegion.list.count; i++){
                polygon.push_back(
                    TwoDLocationAsn_to_TwoDLocation(
                        *region.choice.polygonalRegion.list.array[i]
                    )
                );
            }
            to_return = polygon;
            break;
	    case GeographicRegion_PR_identifiedRegion:
            // TODO: There is no reason for retrocompatibility whilst the region identification is not programmed
            break;
    }
    return to_return;
}

vanetza::security::TwoDLocation TwoDLocationAsn_to_TwoDLocation(const TwoDLocation_t& location){
    vanetza::security::TwoDLocation to_return = vanetza::security::TwoDLocation(vanetza::units::GeoAngle((location.latitude/10000000)*boost::units::degree::degrees),
            vanetza::units::GeoAngle((location.latitude/10000000)*boost::units::degree::degrees));
    return to_return;
}


vanetza::ByteBuffer OCTET_STRING_to_ByteBuffer(const OCTET_STRING_t& octet){
    return ByteBuffer(octet.buf, octet.buf+octet.size);
}

vanetza::security::HashedId8 HashedId8_asn_to_HashedId8(const HashedId8_t& hashed){
    vanetza::security::HashedId8 to_return = vanetza::security::HashedId8{0,0,0,0,0,0,0,0};
    if (hashed.size == 8){
        for(int i =0; i<hashed.size; i++){
            to_return[i] = hashed.buf[i];
        }
    }
    return to_return;
}

vanetza::security::HashedId3 HashedId3_asn_to_HashedId3(const HashedId3_t& hashed){
    vanetza::security::HashedId3 to_return = vanetza::security::HashedId3{0,0,0};
    if (hashed.size == 3){
        for(int i =0; i<hashed.size; i++){
            to_return[i] = hashed.buf[i];
        }
    }
    return to_return;
}

}
}
