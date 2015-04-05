#include <vanetza/security/payload.hpp>
#include <vanetza/security/deserialization_error.hpp>
#include <vanetza/security/length_coding.hpp>

namespace vanetza
{
namespace security
{

PayloadType get_type(const Payload& payload) {
    struct PayloadVisitor: public boost::static_visitor<>
    {
        void operator()(const Unsecured& unsecured) {
            mtype = PayloadType::Unsecured;
        }
        void operator()(const Signed& sign) {
            mtype = PayloadType::Signed;
        }
        void operator()(const Encrypted& encrypted) {
            mtype = PayloadType::Encrypted;
        }
        void operator()(const SignedExternal& external) {
            mtype = PayloadType::Signed_External;
        }
        void operator()(const SignedAndEncrypted& sign) {
            mtype = PayloadType::Signed_And_Encrypted;
        }
        PayloadType mtype;
    };

    PayloadVisitor visit;
    boost::apply_visitor(visit, payload);
    return visit.mtype;
}

size_t get_size(const Payload& payload) {
    struct PayloadVisitor: public boost::static_visitor<>
    {
        void operator()(const Unsecured& unsecured) {
            m_size = unsecured.size();
        }
        void operator()(const Signed& sign) {
            m_size = sign.size();
        }
        void operator()(const Encrypted& encrypted) {
            m_size = encrypted.size();
        }
        void operator()(const SignedExternal& external) {
            m_size = 0;
        }
        void operator()(const SignedAndEncrypted& sign) {
            m_size = sign.size();
        }
        size_t m_size;
    };

    PayloadVisitor visit;
    boost::apply_visitor(visit, payload);
    return visit.m_size + sizeof(PayloadType);
}

size_t get_size(const std::list<Payload>& list) {
    size_t size = 0;
    for(auto elem : list) {
        size += get_size(elem);
    }
    return size;
}

void serialize(OutputArchive& ar, const ByteBuffer& buf) {
    size_t size = buf.size();
    size += get_length_coding_size(size);
    serialize_length(ar, size);
    for (auto& elem : buf) {
        ar << elem;
    }
}

void serialize(OutputArchive& ar, const Payload& payload) {
    struct PayloadVisitor: public boost::static_visitor<>
    {
        PayloadVisitor(OutputArchive& ar) :
            m_archive(ar) {
        }
        void operator()(const Unsecured& unsecured) {
            serialize(m_archive, unsecured);
        }
        void operator()(const Signed& sign) {
            serialize(m_archive, sign);
        }
        void operator()(const Encrypted& encrypted) {
            serialize(m_archive, encrypted);
        }
        void operator()(const SignedExternal& external) {
        }
        void operator()(const SignedAndEncrypted& sign) {
            serialize(m_archive, sign);
        }
        OutputArchive& m_archive;
    };

    PayloadType type = get_type(payload);
    ar << type;
    PayloadVisitor visit(ar);
    boost::apply_visitor(visit, payload);
}

void serialize(OutputArchive& ar, const std::list<Payload> list) {
    size_t size = 0;
    for(auto& payload : list) {
        size += get_size(payload);
    }
    serialize_length(ar, size);
    for(auto& payload : list) {
        serialize(ar, payload);
    }
}

size_t deserialize(InputArchive& ar, ByteBuffer& buf) {
    size_t size = deserialize_length(ar);
    size -= get_length_coding_size(size);
    for (size_t c = 0; c < size; c++) {
        uint8_t elem;
        ar >> elem;
        buf.push_back(elem);
    }
    return size;
}

size_t deserialize(InputArchive& ar, Payload& payload) {
    size_t size= sizeof(PayloadType);
    PayloadType type;
    ar >> type;
    switch (type) {
        case PayloadType::Signed_External:
            break;
        case PayloadType::Unsecured: {
            Unsecured buf;
            size += deserialize(ar, buf);
            payload = buf;
        }
            break;
        case PayloadType::Signed: {
            Signed buf;
            size += deserialize(ar, buf);
            payload = buf;
        }
            break;
        case PayloadType::Encrypted: {
            Encrypted buf;
            size += deserialize(ar, buf);
            payload = buf;
        }
            break;
        case PayloadType::Signed_And_Encrypted: {
            SignedAndEncrypted buf;
            size += deserialize(ar, buf);
            payload = buf;
        }
            break;
        default:
            throw deserialization_error("Unknown PayloadType");
    }

    return size;
}

size_t deserialize(InputArchive& ar, std::list<Payload>& list) {
    size_t size = deserialize_length(ar);
    size_t ret_size = size;
    while(size > 0) {
        Payload payload;
        size -= deserialize(ar, payload);
        list.push_back(payload);
    }
    return ret_size;
}

} // namespace security
} // namespace vanetza

