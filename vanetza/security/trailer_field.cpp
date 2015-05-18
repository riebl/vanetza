#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/length_coding.hpp>

namespace vanetza
{
namespace security
{

TrailerFieldType get_type(const TrailerField& field)
{
    struct trailerFieldVisitor : public boost::static_visitor<TrailerFieldType>
    {
        TrailerFieldType operator()(const Signature& sig)
        {
            return TrailerFieldType::Signature;
        }
    };
    trailerFieldVisitor visit;
    return boost::apply_visitor(visit, field);
}

size_t get_size(const TrailerField& field)
{
    size_t size = sizeof(TrailerFieldType);
    struct trailerFieldVisitor : public boost::static_visitor<size_t>
    {
        size_t operator()(const Signature& sig)
        {
            return get_size(sig);
        }
    };
    trailerFieldVisitor visit;
    size += boost::apply_visitor(visit, field);
    return size;
}

void serialize(OutputArchive& ar, const TrailerField& field)
{
    struct trailerFieldVisitor : public boost::static_visitor<>
    {
        trailerFieldVisitor(OutputArchive& ar) :
            m_archive(ar)
        {
        }
        void operator()(const Signature& sig)
        {
            serialize(m_archive, sig);
        }
        OutputArchive& m_archive;
    };
    TrailerFieldType type = get_type(field);
    serialize(ar, type);
    trailerFieldVisitor visit(ar);
    boost::apply_visitor(visit, field);
}

size_t deserialize(InputArchive& ar, TrailerField& field)
{
    size_t size = 0;
    TrailerFieldType type;
    deserialize(ar, type);
    size += sizeof(TrailerFieldType);
    switch (type) {
        case TrailerFieldType::Signature: {
            Signature sig;
            size += deserialize(ar, sig);
            field = sig;
            break;
        }
        default:
            throw deserialization_error("Unknown TrailerFieldType");
    }
    return size;
}

} // namespace security
} // namespace vanetza
