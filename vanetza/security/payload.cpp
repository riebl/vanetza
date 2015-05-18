#include <vanetza/security/payload.hpp>
#include <vanetza/security/deserialization_error.hpp>
#include <vanetza/security/length_coding.hpp>

namespace vanetza
{
namespace security
{

PayloadType get_type(const Payload& payload)
{
    struct PayloadVisitor : public boost::static_visitor<PayloadType>
    {
        PayloadType operator()(const Unsecured& unsecured)
        {
            return PayloadType::Unsecured;
        }
        PayloadType operator()(const Signed& sign)
        {
            return PayloadType::Signed;
        }
        PayloadType operator()(const Encrypted& encrypted)
        {
            return PayloadType::Encrypted;
        }
        PayloadType operator()(const SignedExternal& external)
        {
            return PayloadType::Signed_External;
        }
        PayloadType operator()(const SignedAndEncrypted& sign)
        {
            return PayloadType::Signed_And_Encrypted;
        }
    };

    PayloadVisitor visit;
    return boost::apply_visitor(visit, payload);
}

size_t get_size(const Payload& payload)
{
    size_t size = sizeof(PayloadType);
    struct PayloadVisitor : public boost::static_visitor<>
    {
        void operator()(const Unsecured& unsecured)
        {
            m_size = unsecured.size();
            m_size += length_coding_size(m_size);
        }
        void operator()(const Signed& sign)
        {
            m_size = sign.size();
            m_size += length_coding_size(m_size);
        }
        void operator()(const Encrypted& encrypted)
        {
            m_size = encrypted.size();
            m_size += length_coding_size(m_size);
        }
        void operator()(const SignedExternal& external)
        {
            m_size = 0;
        }
        void operator()(const SignedAndEncrypted& sign)
        {
            m_size = sign.size();
            m_size += length_coding_size(m_size);
        }
        size_t m_size;
    };

    PayloadVisitor visit;
    boost::apply_visitor(visit, payload);
    size += visit.m_size;
    return size;
}

size_t get_size(const ByteBuffer& buf)
{
    size_t size = buf.size();
    size += length_coding_size(size);
    return size;
}

void serialize(OutputArchive& ar, const ByteBuffer& buf)
{
    size_t size = buf.size();
    serialize_length(ar, size);
    for (auto& elem : buf) {
        ar << elem;
    }
}

void serialize(OutputArchive& ar, const Payload& payload)
{
    struct PayloadVisitor : public boost::static_visitor<>
    {
        PayloadVisitor(OutputArchive& ar) :
            m_archive(ar)
        {
        }
        void operator()(const Unsecured& unsecured)
        {
            serialize(m_archive, unsecured);
        }
        void operator()(const Signed& sign)
        {
            serialize(m_archive, sign);
        }
        void operator()(const Encrypted& encrypted)
        {
            serialize(m_archive, encrypted);
        }
        void operator()(const SignedExternal& external)
        {
        }
        void operator()(const SignedAndEncrypted& sign)
        {
            serialize(m_archive, sign);
        }
        OutputArchive& m_archive;
    };

    PayloadType type = get_type(payload);
    serialize(ar, type);
    PayloadVisitor visit(ar);
    boost::apply_visitor(visit, payload);
}


size_t deserialize(InputArchive& ar, ByteBuffer& buf)
{
    size_t size = deserialize_length(ar);
    size_t ret_size = size;
    ret_size += length_coding_size(size);
    for (size_t c = 0; c < size; c++) {
        uint8_t elem;
        ar >> elem;
        buf.push_back(elem);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, Payload& payload)
{
    size_t size = sizeof(PayloadType);
    PayloadType type;
    deserialize(ar, type);
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

} // namespace security
} // namespace vanetza

