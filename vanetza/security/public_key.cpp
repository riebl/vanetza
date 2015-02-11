#include <vanetza/security/public_key.hpp>

namespace vanetza {
namespace security {

PublicKeyAlgorithm get_type(const PublicKey& key) {
    struct public_key_visitor: public boost::static_visitor<> {
        void operator()(const ecdsa_nistp256_with_sha256& ecdsa) {
            m_type = PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256;
        }
        void operator()(const ecies_nistp256& ecies) {
            m_type = PublicKeyAlgorithm::Ecies_Nistp256;
        }
        PublicKeyAlgorithm m_type;
    };

    public_key_visitor visit;
    boost::apply_visitor(visit, key);
    return visit.m_type;
}

void serialize(OutputArchive& ar, const PublicKey& key) {
    struct public_key_visitor: public boost::static_visitor<> {
        public_key_visitor(OutputArchive& ar) :
                m_archive(ar) {
        }
        void operator()(const ecdsa_nistp256_with_sha256& ecdsa) {
            serialize(m_archive, ecdsa.public_key);
        }
        void operator()(const ecies_nistp256& ecies) {
            m_archive << ecies.supported_symm_alg;
            serialize(m_archive, ecies.public_key);
        }
        OutputArchive& m_archive;
    };

    PublicKeyAlgorithm type = get_type(key);
    ar << type;
    public_key_visitor visit(ar);
    boost::apply_visitor(visit, key);
}

std::size_t field_size(PublicKeyAlgorithm algo) {
    size_t size = 0;
    switch (algo) {
    case PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256:
        size = 32;
        break;
    case PublicKeyAlgorithm::Ecies_Nistp256:
        size = 32;
        break;
    }
    return size;
}

size_t deserialize(InputArchive& ar, PublicKey& key) {
    PublicKeyAlgorithm type;
    ar >> type;
    switch (type) {
    case PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256: {
        ecdsa_nistp256_with_sha256 ecdsa;
        deserialize(ar, ecdsa.public_key,
                PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256);
        key = ecdsa;
        break;
    }
    case PublicKeyAlgorithm::Ecies_Nistp256: {
        ecies_nistp256 ecies;
        ar >> ecies.supported_symm_alg;
        deserialize(ar, ecies.public_key, PublicKeyAlgorithm::Ecies_Nistp256);
        key = ecies;
        break;
    }
    default:
        throw deserialization_error("Unknown PublicKeyAlgortihm");
    }
    return get_size(key);
}

size_t get_size(const PublicKey& key) {
    PublicKeyAlgorithm type;
    type = get_type(key);
    size_t size = 0;
    size += sizeof(type);
    switch (type) {
    case PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256:
        size += get_size(
                boost::get<ecdsa_nistp256_with_sha256>(key).public_key);
        break;
    case PublicKeyAlgorithm::Ecies_Nistp256:
        size += get_size(boost::get<ecies_nistp256>(key).public_key);
        size += sizeof(boost::get<ecies_nistp256>(key).supported_symm_alg);
        break;
    }
    return size;
}

} // namespace security
} // namespace vanetza

