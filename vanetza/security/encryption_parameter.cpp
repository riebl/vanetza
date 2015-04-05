#include <vanetza/security/encryption_parameter.hpp>
#include <vanetza/security/public_key.hpp>

namespace vanetza
{
namespace security
{

SymmetricAlgorithm get_type(const EncryptionParameter& param) {
    struct Encryption_visitor : public boost::static_visitor<>
    {
        void operator()(const Nonce& nonce) {
            m_algo = SymmetricAlgorithm::Aes128_Ccm;
        }
        SymmetricAlgorithm m_algo;
    };

    Encryption_visitor visit;
    boost::apply_visitor(visit, param);
    return visit.m_algo;
}

void serialize(OutputArchive& ar, const EncryptionParameter& param) {
    struct Encryption_visitor : public boost::static_visitor<>
    {
        Encryption_visitor(OutputArchive& ar) :
                m_archive(ar) {
        }
        void operator()(const Nonce& nonce) {
            for (auto& byte : nonce) {
                m_archive << byte;
            }
        }
        OutputArchive& m_archive;
    };

    SymmetricAlgorithm algo = get_type(param);
    ar << algo;
    Encryption_visitor visit(ar);
    boost::apply_visitor(visit, param);
}

size_t get_size(const EncryptionParameter& param) {
    struct Encryption_visitor : public boost::static_visitor<>
    {
        void operator()(const Nonce& nonce) {
            m_size = nonce.size();
        }
        size_t m_size;
    };

    Encryption_visitor visit;
    boost::apply_visitor(visit, param);
    return visit.m_size;
}

size_t deserialize(InputArchive& ar, EncryptionParameter& param, SymmetricAlgorithm& sym) {
    SymmetricAlgorithm algo;
    ar >> algo;
    switch (algo) {
        case SymmetricAlgorithm::Aes128_Ccm: {
            Nonce nonce;
            for (size_t s = 0; s < nonce.size(); s++) {
                ar >> nonce[s];
            }
            sym = SymmetricAlgorithm::Aes128_Ccm;
            param = nonce;
            break;
        }
        default:
            throw deserialization_error("Unknown Symmetric Algorithm");
            break;
    }
    return get_size(param);
}

} // namespace security
} // namespace vanetza
