#include <vanetza/security/validity_restriction.hpp>

namespace vanetza
{
namespace security
{

Duration::Duration() :
        m_unit(Units::Seconds), m_uint16(0) {
}

Duration::Duration(BitNumber<uint16_t, 13> value, Units unit) :
        m_unit(unit), m_value(value) {
    uint16_t tmp = uint16_t(m_unit) << 13;
    m_uint16 = m_value.raw() | tmp;
}

Duration::Duration(uint16_t uint16) :
        m_uint16(uint16) {
    m_value = BitNumber<uint16_t, 13>(uint16);
    m_unit = Units(uint16 >> 13);
}

ValidityRestrictionType get_type(const ValidityRestriction& restriction) {
    struct validity_restriction_visitor: public boost::static_visitor<>
    {
        void operator()(const EndValidity& validity) {
            m_type = ValidityRestrictionType::Time_End;
        }
        void operator()(const StartAndEndValidity& validity) {
            m_type = ValidityRestrictionType::Time_Start_And_End;
        }
        void operator()(const StartAndDurationValidity& validity) {
            m_type = ValidityRestrictionType::Time_Start_And_Duration;
        }
        void operator()(const GeograpicRegion& region) {
            m_type = ValidityRestrictionType::Region;
        }
        ValidityRestrictionType m_type;
    };

    validity_restriction_visitor visit;
    boost::apply_visitor(visit, restriction);
    return visit.m_type;
}

size_t get_size(const Time32& time) {
    return sizeof(Time32);
}

size_t get_size(const Time64& time) {
    return sizeof(Time64);
}

size_t get_size(const Duration& duration) {
    return sizeof(uint16_t);
}

size_t get_size(const StartAndEndValidity& validity) {
    size_t size = sizeof(validity.end_validity);
    size += sizeof(validity.start_validity);
    return size;
}

size_t get_size(const StartAndDurationValidity& validity) {
    size_t size = sizeof(validity.start_validity);
    size += get_size(validity.duration);
    return size;
}

size_t get_size(const ValidityRestriction& restriction) {
    struct validity_restriction_visitor: public boost::static_visitor<>
    {
        void operator()(const EndValidity& validity) {
            m_size = sizeof(validity);
        }
        void operator()(const StartAndEndValidity& validity) {
            m_size = get_size(validity);
        }
        void operator()(const StartAndDurationValidity& validity) {
            m_size = get_size(validity);
        }
        void operator()(const GeograpicRegion& region) {
            m_size = get_size(region);
        }
        size_t m_size;
    };

    validity_restriction_visitor visit;
    boost::apply_visitor(visit, restriction);
    return visit.m_size;
}

size_t deserialize(InputArchive& ar, std::list<ValidityRestriction>& restrictionList) {
    size_t size = deserialize_length(ar);
    size_t retSize = size;
    ValidityRestrictionType type;
    while (size > 0) {
        ValidityRestriction restriction;
        ar >> type;
        switch (type) {
            case ValidityRestrictionType::Time_End: {
                EndValidity end;
                geonet::deserialize(end, ar);
                size -= sizeof(end);
                restriction = end;
                restrictionList.push_back(end);
                break;
            }
            case ValidityRestrictionType::Time_Start_And_Duration: {
                StartAndDurationValidity validity;
                geonet::deserialize(validity.start_validity, ar);
                uint16_t duration;
                geonet::deserialize(duration, ar);
                ;
                validity.duration = Duration(duration);
                size -= get_size(validity);
                restriction = validity;
                restrictionList.push_back(validity);
                break;
            }
            case ValidityRestrictionType::Time_Start_And_End: {
                StartAndEndValidity validity;
                geonet::deserialize(validity.start_validity, ar);
                geonet::deserialize(validity.end_validity, ar);
                restriction = validity;
                restrictionList.push_back(restriction);
                size -= get_size(validity);
                break;
            }
            case ValidityRestrictionType::Region: {
                GeograpicRegion region;
                deserialize(ar, region);
                restriction = region;
                restrictionList.push_back(restriction);
                size -= get_size(region);
                break;
            }
            default:
                throw deserialization_error("Unknown ValidityRestrictionType");
        }
    }
    return retSize;
}

void serialize(OutputArchive& ar, const std::list<ValidityRestriction>& restrictionList) {
    size_t size = 0;
    for (auto& restriction : restrictionList) {
        size += get_size(restriction);
    }
    serialize_length(ar, size);

    for (auto& restriction : restrictionList) {
        struct validity_restriction_visitor: public boost::static_visitor<>
        {
            validity_restriction_visitor(OutputArchive& ar) :
                    m_archive(ar) {
            }
            void operator()(const EndValidity& validity) {
                geonet::serialize(host_cast(validity), m_archive);
            }
            void operator()(const StartAndEndValidity& validity) {
                geonet::serialize(host_cast(validity.start_validity), m_archive);
                geonet::serialize(host_cast(validity.end_validity), m_archive);
            }
            void operator()(const StartAndDurationValidity& validity) {
                geonet::serialize(host_cast(validity.start_validity), m_archive);
                geonet::serialize(host_cast(validity.duration.raw()), m_archive);
            }
            void operator()(const GeograpicRegion& region) {
                serialize(m_archive, region);
            }
            OutputArchive& m_archive;
        };

        ValidityRestrictionType type = get_type(restriction);
        ar << type;
        validity_restriction_visitor visit(ar);
        boost::apply_visitor(visit, restriction);
    }
}

} // namespace security
} // namespace vanetza
