#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/length_coding.hpp>

namespace vanetza
{
namespace security
{

TrailerFieldType get_type(const TrailerField& field) {
    struct trailerFieldVisitor: public boost::static_visitor<>
    {
        void operator()(const Signature& sig) {
            m_type = TrailerFieldType::Signature;
        }
        TrailerFieldType m_type;
    };
    trailerFieldVisitor visit;
    boost::apply_visitor(visit, field);
    return visit.m_type;
}

size_t get_size(const TrailerField& field) {
    struct trailerFieldVisitor: public boost::static_visitor<>
    {
        void operator()(const Signature& sig) {
            m_size = get_size(sig);
        }
        size_t m_size;
    };
    trailerFieldVisitor visit;
    boost::apply_visitor(visit, field);
    return visit.m_size + sizeof(TrailerFieldType);
}

size_t get_size(const std::list<TrailerField>& list) {
    size_t size = 0;
    for(auto elem : list ) {
        size += get_size(elem);
    }
    return size;
}

void serialize(OutputArchive& ar,const std::list<TrailerField>& list) {
    size_t size = 0;
    for (auto& field : list) {
        size += get_size(field);
    }
    serialize_length(ar, size);
    for (auto& field : list) {
        serialize(ar, field);
    }
}

void serialize(OutputArchive& ar, const TrailerField& field) {
    struct trailerFieldVisitor: public boost::static_visitor<>
    {
        trailerFieldVisitor(OutputArchive& ar) : m_archive(ar) {}
        void operator()(const Signature& sig) {
            serialize(m_archive, sig);
        }
        OutputArchive& m_archive;
    };
    TrailerFieldType type = get_type(field);
    ar << type;
    trailerFieldVisitor visit(ar);
    boost::apply_visitor(visit, field);
}

size_t deserialize(InputArchive& ar, std::list<TrailerField>& list) {
    size_t size = deserialize_length(ar);
    size_t ret_size = size;
    while (size > 0) {
        TrailerField field;
        size -= deserialize(ar, field);
        list.push_back(field);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, TrailerField& field) {
    size_t size = 0;
    TrailerFieldType type;
    ar >> type;
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
