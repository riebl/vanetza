#include <vanetza/security/exception.hpp>
#include <vanetza/security/v2/signature.hpp>
#include <boost/iostreams/stream.hpp>
#include <cassert>

namespace vanetza
{
namespace security
{
namespace v2
{

PublicKeyAlgorithm get_type(const Signature& sig)
{
    struct Signature_visitor : public boost::static_visitor<PublicKeyAlgorithm>
    {
        PublicKeyAlgorithm operator()(const EcdsaSignature& sig)
        {
            return PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
        }

        PublicKeyAlgorithm operator()(const EcdsaSignatureFuture& sig)
        {
            return PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
        }
    };
    Signature_visitor visit;
    return boost::apply_visitor(visit, sig.some_ecdsa);
}

size_t get_size(const EcdsaSignature& sig)
{
    size_t size = sig.s.size();
    size += get_size(sig.R);
    return size;
}

size_t get_size(const EcdsaSignatureFuture& sig)
{
    return sig.size();
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

        size_t operator()(const EcdsaSignatureFuture& sig)
        {
            return get_size(sig);
        }
    };
    Signature_visitor visit;
    size += boost::apply_visitor(visit, sig.some_ecdsa);
    return size;
}

void serialize(OutputArchive& ar, const Signature& sig)
{
    struct signature_visitor : public boost::static_visitor<>
    {
        signature_visitor(OutputArchive& ar) : m_archive(ar) {}

        void operator()(const EcdsaSignature& sig)
        {
            serialize(m_archive, sig);
        }

        void operator()(const EcdsaSignatureFuture& sig)
        {
            serialize(m_archive, sig);
        }

        OutputArchive& m_archive;
    };

    PublicKeyAlgorithm algo = get_type(sig);
    serialize(ar, algo);
    signature_visitor visitor(ar);
    boost::apply_visitor(visitor, sig.some_ecdsa);
}

void serialize(OutputArchive& ar, const EcdsaSignature& sig)
{
    const PublicKeyAlgorithm algo = PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
    assert(field_size(algo) == sig.s.size());

    serialize(ar, sig.R, algo);
    for (auto& byte : sig.s) {
        ar << byte;
    }
}

void serialize(OutputArchive& ar, const EcdsaSignatureFuture& sig)
{
    auto& ecdsa = sig.get();
    serialize(ar, ecdsa);
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
        case PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256: {
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

boost::optional<EcdsaSignature> extract_ecdsa_signature(const Signature& sig)
{
    struct signature_visitor : public boost::static_visitor<const EcdsaSignature*>
    {
        const EcdsaSignature* operator()(const EcdsaSignature& sig)
        {
            return &sig;
        }

        const EcdsaSignature* operator()(const EcdsaSignatureFuture& sig)
        {
            return &sig.get();
        }
    };

    signature_visitor visitor;
    const EcdsaSignature* ecdsa = boost::apply_visitor(visitor, sig.some_ecdsa);
    return boost::optional<EcdsaSignature>(ecdsa != nullptr, *ecdsa);
}

} // namespace v2
} // namespace security
} // namespace vanetza
