#include <vanetza/security/signature.hpp>

namespace vanetza
{
namespace security
{

PublicKeyAlgorithm get_type(const Signature& sig)
{
    struct Signature_visitor : public boost::static_visitor<PublicKeyAlgorithm>
    {
        PublicKeyAlgorithm operator()(const EcdsaSignature& sig)
        {
            return PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256;
        }
    };
    Signature_visitor visit;
    return boost::apply_visitor(visit, sig);
}

size_t get_size(const EcdsaSignature& sig)
{
    size_t size = sig.s.size();
    size += get_size(sig.R);
    return size;
}

size_t get_size(const Signature& sig)
{
    size_t size = sizeof(PublicKeyAlgorithm);
    struct Signature_visitor : public boost::static_visitor<size_t>
    {
        size_t operator()(const EcdsaSignature& sig)
        {
            return get_size(sig);
        }
    };
    Signature_visitor visit;
    size += boost::apply_visitor(visit, sig);
    return size;
}

void serialize(OutputArchive& ar, const Signature& sig)
{
    struct Signature_visitor : public boost::static_visitor<>
    {
        Signature_visitor(OutputArchive& ar) :
            m_archive(ar)
        {
        }
        void operator()(const EcdsaSignature& sig)
        {
            serialize(m_archive, sig.R);
            for (auto& byte : sig.s) {
                m_archive << byte;
            }
        }
        OutputArchive& m_archive;
    };
    PublicKeyAlgorithm algo = get_type(sig);
    serialize(ar, algo);
    Signature_visitor visit(ar);
    boost::apply_visitor(visit, sig);
}

size_t deserialize(InputArchive& ar, EcdsaSignature& sig, const PublicKeyAlgorithm& algo)
{
    EccPoint point;
    ByteBuffer buf;
    deserialize(ar, point, algo);
    for (size_t i = 0; i < field_size(algo); i++) {
        uint8_t byte;
        ar >> byte;
        buf.push_back(byte);
    }
    sig.R = point;
    sig.s = buf;
    return get_size(sig);
}

size_t deserialize(InputArchive& ar, Signature& sig)
{
    PublicKeyAlgorithm algo;
    size_t size = 0;
    deserialize(ar, algo);
    size += sizeof(algo);
    switch (algo) {
        case PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256: {
            EcdsaSignature signature;
            size += deserialize(ar, signature, algo);
            sig = signature;
            break;
        }
        default:
            throw deserialization_error("Unknown PublicKeyAlgorithm");
    }
    return size;
}

} // ns security
} // ns vanetza
