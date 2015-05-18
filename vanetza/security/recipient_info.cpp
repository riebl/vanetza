#include <vanetza/security/recipient_info.hpp>
#include <vanetza/security/length_coding.hpp>

namespace vanetza
{
namespace security
{

PublicKeyAlgorithm get_type(const RecipientInfo& info)
{
    struct RecipientInfoKey_visitor : public boost::static_visitor<PublicKeyAlgorithm>
    {
        PublicKeyAlgorithm operator()(const EciesNistP256EncryptedKey& key)
        {
            return PublicKeyAlgorithm::Ecies_Nistp256;
        }
    };

    RecipientInfoKey_visitor visit;
    return boost::apply_visitor(visit, info.enc_key);
}

size_t get_size(const RecipientInfo& info)
{
    size_t size = info.cert_id.size();
    size += sizeof(PublicKeyAlgorithm);
    struct RecipientInfoKey_visitor : public boost::static_visitor<>
    {
        void operator()(const EciesNistP256EncryptedKey& key)
        {
            m_size = key.c.size();
            m_size += key.t.size();
            m_size += get_size(key.v);
        }
        size_t m_size;
    };

    RecipientInfoKey_visitor visit;
    boost::apply_visitor(visit, info.enc_key);
    size += visit.m_size;
    return size;
}

void serialize(OutputArchive& ar, const RecipientInfo& info)
{
    struct RecipientInfo_visitor : public boost::static_visitor<>
    {
        RecipientInfo_visitor(OutputArchive& ar) :
            m_archive(ar)
        {
        }
        void operator()(const EciesNistP256EncryptedKey& key)
        {
            for (auto& byte : key.c) {
                m_archive << byte;
            }
            for (auto& byte : key.t) {
                m_archive << byte;
            }
            serialize(m_archive, key.v);
        }
        OutputArchive& m_archive;
    };
    for (auto& byte : info.cert_id) {
        ar << byte;
    }
    PublicKeyAlgorithm algo = get_type(info);
    serialize(ar, algo);
    RecipientInfo_visitor visit(ar);
    boost::apply_visitor(visit, info.enc_key);
}

size_t deserialize(InputArchive& ar, std::list<RecipientInfo>& list,
    const SymmetricAlgorithm& symAlgo)
{
    size_t size = deserialize_length(ar);
    size_t ret_size = size;
    while (size > 0) {
        RecipientInfo info;
        size -= deserialize(ar, info, symAlgo);
        list.push_back(info);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, RecipientInfo& info, const SymmetricAlgorithm& symAlgo)
{
    size_t fieldSize;
    switch (symAlgo) {
        case SymmetricAlgorithm::Aes128_Ccm:
            fieldSize = 16;
            break;
        default:
            throw deserialization_error("Unknown SymmetricAlgorithm");
    }
    for (int c = 0; c < 8; c++) {
        ar >> info.cert_id[c];
    }
    PublicKeyAlgorithm algo;
    deserialize(ar, algo);
    switch (algo) {
        case PublicKeyAlgorithm::Ecies_Nistp256:
            for (int c = 0; c < fieldSize; c++) {
                uint8_t tmp;
                ar >> tmp;
                boost::get<EciesNistP256EncryptedKey>(info.enc_key).c.push_back(tmp);
            }
            for (int c = 0; c < 20; c++) {
                uint8_t tmp;
                ar >> tmp;
                boost::get<EciesNistP256EncryptedKey>(info.enc_key).t.push_back(tmp);
            }
            deserialize(ar, boost::get<EciesNistP256EncryptedKey>(info.enc_key).v,
                PublicKeyAlgorithm::Ecies_Nistp256);
            break;
        default:
            throw deserialization_error("Unknown PublicKeyAlgoritm");
    }

    return get_size(info);
}

} // namespace security
} // namespace vanetza
