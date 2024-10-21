#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <boost/optional/optional.hpp>
#include <cryptopp/oids.h>
#include <algorithm>
#include <cassert>
#include <iterator>
#include <functional>

namespace vanetza
{
namespace security
{

namespace {

/**
 * Derive Crypto++ OID object from key type
 * \param key_type key type from our API
 * \return Crypto++ OID object (possibly empty)
 */
CryptoPP::OID get_oid(KeyType key_type)
{
    if (key_type == KeyType::NistP256) {
        return CryptoPP::ASN1::secp256r1();
    } else if (key_type == KeyType::BrainpoolP256r1) {
        return CryptoPP::ASN1::brainpoolP256r1();
    } else if (key_type == KeyType::BrainpoolP384r1) {
        return CryptoPP::ASN1::brainpoolP384r1();
    } else {
        return CryptoPP::OID {};
    }
}

/**
 * Encode public key with prefix byte
 * - 0x02 compressed with Y0
 * - 0x03 compressed with Y1
 * - 0x04 uncompressed
 *
 * \param pub_key generic public key
 * \return encoded public key
 */
ByteBuffer encode_public_key(const PublicKey& pub_key)
{
    ByteBuffer encoded;

    if (pub_key.compression == KeyCompression::NoCompression) {
        encoded.reserve(1 + pub_key.x.size() + pub_key.y.size());
        encoded.push_back(0x04);
        encoded.insert(encoded.end(), pub_key.x.begin(), pub_key.x.end());
        encoded.insert(encoded.end(), pub_key.y.begin(), pub_key.y.end());
    } else if (pub_key.compression == KeyCompression::Y0) {
        encoded.reserve(1 + pub_key.x.size());
        encoded.push_back(0x02);
        encoded.insert(encoded.end(), pub_key.x.begin(), pub_key.x.end());
    } else if (pub_key.compression == KeyCompression::Y1) {
        encoded.reserve(1 + pub_key.x.size());
        encoded.push_back(0x03);
        encoded.insert(encoded.end(), pub_key.x.begin(), pub_key.x.end());
    }

    return encoded;
}

using InternalPublicKey = CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>;
using InternalPrivateKey = CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>;

/**
 * Convert our PublicKey type to a Crypto++ EC public key
 * \param pub_key our public key
 * \return public key as Crypto++ type (if conversion was possible)
 */
boost::optional<InternalPublicKey> convert_public_key(const PublicKey& pub_key)
{
    InternalPublicKey out;
    out.AccessGroupParameters().Initialize(get_oid(pub_key.type));
    auto& curve = out.GetGroupParameters().GetCurve();
    
    CryptoPP::ECP::Point point;
    ByteBuffer encoded_pub_key = encode_public_key(pub_key);
    CryptoPP::StringStore store { encoded_pub_key.data(), encoded_pub_key.size() };
    if (!curve.DecodePoint(point, store, store.MaxRetrievable())) {
        return boost::none;
    }
    out.SetPublicElement(point);
    return out;
}

/**
 * Convert our PrivateKey type to a Crypto++ EC private key
 * \param priv_key our private key
 * \return private key as Crypto++ type
 */
InternalPrivateKey convert_private_key(const PrivateKey& priv_key)
{
    InternalPrivateKey out;
    out.AccessGroupParameters().Initialize(get_oid(priv_key.type));
    out.SetPrivateExponent(CryptoPP::Integer(priv_key.key.data(), priv_key.key.size()));
    return out;
}

/**
 * Specialized Crypto++ Verifier for C-ITS messages
 */
template<typename ECDSA>
class Verifier : public ECDSA::Verifier
{
public:
    using BaseVerifier = typename ECDSA::Verifier;

    /**
     * Construct verifier object for a public key
     * \param pub public key
     */
    Verifier(const InternalPublicKey& pub)
        : BaseVerifier(pub)
    {
    }

    /**
     * Verify digest and signature
     * \param digest hash of to-be-verified data
     * \param sig given signature
     * \return true if digest, signature and public key match
     */
    bool VerifyDigest(const ByteBuffer& digest, const Signature& sig)
    {
        using namespace CryptoPP;
        const auto& alg = this->GetSignatureAlgorithm();
        const auto& params = this->GetAbstractGroupParameters();
        const auto& key = this->GetKeyInterface();
        this->GetMaterial().DoQuickSanityCheck();

        Integer e { digest.data(), digest.size() };
        Integer r { sig.r.data(), sig.r.size() };
        Integer s { sig.s.data(), sig.s.size() };
        return alg.Verify(params, key, e, r, s);
    }
};

template<size_t N>
class IdentityHash : public CryptoPP::HashTransformation
{
public:
    CRYPTOPP_CONSTANT(DIGESTSIZE = N);

    static const char* StaticAlgorithmName()
    {
        return "IdentityHash";
    }

    void Update(const uint8_t* input, size_t length) override
    {
        std::copy_n(input, std::min(length, m_hash.size()), m_hash.begin());;
    }

    void TruncatedFinal(uint8_t* output, size_t len) override
    {
        if (output != nullptr) {
            std::copy_n(m_hash.begin(), std::min(len, m_hash.size()), output);
        }
        m_hash.fill(0);
    }

    unsigned int DigestSize() const override
    {
        return m_hash.size();
    }

private:
    std::array<uint8_t, N> m_hash;
};

template<size_t N>
using DigestEcdsa = CryptoPP::ECDSA<CryptoPP::ECP, IdentityHash<N>>;

} // namespace

using std::placeholders::_1;

BackendCryptoPP::BackendCryptoPP()
{
}

EcdsaSignature BackendCryptoPP::sign_data(const ecdsa256::PrivateKey& generic_key, const ByteBuffer& data)
{
    return sign_data(internal_private_key(generic_key), data);
}

EcdsaSignature BackendCryptoPP::sign_data(const Ecdsa256::PrivateKey& private_key, const ByteBuffer& data)
{
    // calculate signature
    Ecdsa256::Signer signer(private_key);
    ByteBuffer signature(signer.MaxSignatureLength(), 0x00);
    auto signature_length = signer.SignMessage(m_prng, data.data(), data.size(), signature.data());
    signature.resize(signature_length);

    auto signature_delimiter = signature.begin();
    std::advance(signature_delimiter, 32);

    EcdsaSignature ecdsa_signature;
    // set R
    X_Coordinate_Only coordinate;
    coordinate.x = ByteBuffer(signature.begin(), signature_delimiter);
    ecdsa_signature.R = std::move(coordinate);
    // set s
    ByteBuffer trailer_field_buffer(signature_delimiter, signature.end());
    ecdsa_signature.s = std::move(trailer_field_buffer);

    return ecdsa_signature;
}

Signature BackendCryptoPP::sign_digest(const PrivateKey& private_key, const ByteBuffer& digest)
{
    static const Signature dummy = {};

    CryptoPP::DL_Keys_ECDSA<CryptoPP::ECP>::PrivateKey key;
    CryptoPP::Integer integer { private_key.key.data(), private_key.key.size() };

    if (private_key.type == KeyType::NistP256) {
        CryptoPP::Integer integer { private_key.key.data(), private_key.key.size() };
        key.Initialize(CryptoPP::ASN1::secp256r1(), integer);
    } else if (private_key.type == KeyType::BrainpoolP256r1) {
        CryptoPP::Integer integer { private_key.key.data(), private_key.key.size() };
        key.Initialize(CryptoPP::ASN1::brainpoolP256r1(), integer);
    } else if (private_key.type == KeyType::BrainpoolP384r1) {
        CryptoPP::Integer integer { private_key.key.data(), private_key.key.size() };
        key.Initialize(CryptoPP::ASN1::brainpoolP384r1(), integer);
    } else {
        return dummy;
    }

    auto calculate_signature = [&](CryptoPP::PK_Signer* signer) -> Signature
    {
        // calculate signature
        ByteBuffer signature(signer->MaxSignatureLength(), 0x00);
        auto signature_length = signer->SignMessage(m_prng, digest.data(), digest.size(), signature.data());
        signature.resize(signature_length);

        auto signature_delimiter = signature.begin();
        std::advance(signature_delimiter, signer->MaxSignatureLength() / 2);

        Signature ecdsa_signature;
        ecdsa_signature.type = private_key.type;
        ecdsa_signature.r = ByteBuffer(signature.begin(), signature_delimiter);
        ecdsa_signature.s = ByteBuffer(signature_delimiter, signature.end());
        return ecdsa_signature;
    };

    if (digest.size() == 32) {
        DigestEcdsa<32>::Signer signer(key);
        return calculate_signature(&signer);
    } else if (digest.size() == 48) {
        DigestEcdsa<48>::Signer signer(key);
        return calculate_signature(&signer);
    } else {
        return dummy;
    }
}

bool BackendCryptoPP::verify_data(const ecdsa256::PublicKey& generic_key, const ByteBuffer& msg, const EcdsaSignature& sig)
{
    const ByteBuffer sigbuf = extract_signature_buffer(sig);
    return verify_data(internal_public_key(generic_key), msg, sigbuf);
}

bool BackendCryptoPP::verify_digest(const PublicKey& public_key, const ByteBuffer& digest, const Signature& sig)
{
    if (public_key.type != sig.type) {
        return false;
    }

    boost::optional<InternalPublicKey> internal_pub_key = convert_public_key(public_key);
    if (!internal_pub_key) {
        return false;
    } else if (!internal_pub_key->Validate(m_prng, 3)) {
        return false;
    }

    if (sig.type == KeyType::NistP256 || sig.type == KeyType::BrainpoolP256r1) {
        Verifier<Ecdsa256> verifier(*internal_pub_key);
        return verifier.VerifyDigest(digest, sig);
    } else if (sig.type == KeyType::BrainpoolP384r1) {
        Verifier<Ecdsa384> verifier(*internal_pub_key);
        return verifier.VerifyDigest(digest, sig);
    }

    return false;
}

bool BackendCryptoPP::verify_data(const Ecdsa256::PublicKey& public_key, const ByteBuffer& msg, const ByteBuffer& sig)
{
    Ecdsa256::Verifier verifier(public_key);
    return verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());
}

boost::optional<Uncompressed> BackendCryptoPP::decompress_point(const EccPoint& ecc_point)
{
    struct DecompressionVisitor : public boost::static_visitor<bool>
    {
        bool operator()(const X_Coordinate_Only&)
        {
            return false;
        }

        bool operator()(const Compressed_Lsb_Y_0& p)
        {
            decompress(p.x, 0x02);
            return true;
        }

        bool operator()(const Compressed_Lsb_Y_1& p)
        {
            decompress(p.x, 0x03);
            return true;
        }

        bool operator()(const Uncompressed& p)
        {
            result = p;
            return true;
        }

        void decompress(const ByteBuffer& x, ByteBuffer::value_type type)
        {
            ByteBuffer compact;
            compact.reserve(x.size() + 1);
            compact.push_back(type);
            std::copy(x.begin(), x.end(), std::back_inserter(compact));

            CryptoPP::ECP::Point point;
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group(CryptoPP::ASN1::secp256r1());
            group.GetCurve().DecodePoint(point, compact.data(), compact.size());

            result.x = x;
            result.y.resize(result.x.size());
            point.y.Encode(result.y.data(), result.y.size());
        }

        Uncompressed result;
    };

    DecompressionVisitor visitor;
    if (boost::apply_visitor(visitor, ecc_point)) {
        return visitor.result;
    } else {
        return boost::none;
    }
}

ByteBuffer BackendCryptoPP::calculate_hash(HashAlgorithm algo_id, const ByteBuffer& buffer)
{
    ByteBuffer hash;
    if (algo_id == HashAlgorithm::SHA256) {
        CryptoPP::SHA256 algo;
        hash.resize(algo.DigestSize());
        algo.CalculateDigest(hash.data(), buffer.data(), buffer.size());
    } else if (algo_id == HashAlgorithm::SHA384) {
        CryptoPP::SHA384 algo;
        hash.resize(algo.DigestSize());
        algo.CalculateDigest(hash.data(), buffer.data(), buffer.size());
    }
    return hash;
}

ecdsa256::KeyPair BackendCryptoPP::generate_key_pair()
{
    ecdsa256::KeyPair kp;
    auto private_key = generate_private_key();
    auto& private_exponent = private_key.GetPrivateExponent();
    assert(kp.private_key.key.size() >= private_exponent.ByteCount());
    private_exponent.Encode(kp.private_key.key.data(), kp.private_key.key.size());

    auto public_key = generate_public_key(private_key);
    auto& public_element = public_key.GetPublicElement();
    assert(kp.public_key.x.size() >= public_element.x.ByteCount());
    assert(kp.public_key.y.size() >= public_element.y.ByteCount());
    public_element.x.Encode(kp.public_key.x.data(), kp.public_key.x.size());
    public_element.y.Encode(kp.public_key.y.data(), kp.public_key.y.size());
    return kp;
}

BackendCryptoPP::Ecdsa256::PrivateKey BackendCryptoPP::generate_private_key()
{
    CryptoPP::OID oid(CryptoPP::ASN1::secp256r1());
    Ecdsa256::PrivateKey private_key;
    private_key.Initialize(m_prng, oid);
    assert(private_key.Validate(m_prng, 3));
    return private_key;
}

BackendCryptoPP::Ecdsa256::PublicKey BackendCryptoPP::generate_public_key(const Ecdsa256::PrivateKey& private_key)
{
    Ecdsa256::PublicKey public_key;
    private_key.MakePublicKey(public_key);
    assert(public_key.Validate(m_prng, 3));
    return public_key;
}

BackendCryptoPP::Ecdsa256::PublicKey BackendCryptoPP::internal_public_key(const ecdsa256::PublicKey& generic)
{
    CryptoPP::Integer x { generic.x.data(), generic.x.size() };
    CryptoPP::Integer y { generic.y.data(), generic.y.size() };
    CryptoPP::ECP::Point q { x, y };

    Ecdsa256::PublicKey pub;
    pub.Initialize(CryptoPP::ASN1::secp256r1(), q);
    assert(pub.Validate(m_prng, 3));
    return pub;
}

BackendCryptoPP::Ecdsa256::PrivateKey BackendCryptoPP::internal_private_key(const ecdsa256::PrivateKey& generic)
{
    Ecdsa256::PrivateKey key;
    CryptoPP::Integer integer { generic.key.data(), generic.key.size() };
    key.Initialize(CryptoPP::ASN1::secp256r1(), integer);
    return key;
}

} // namespace security
} // namespace vanetza
