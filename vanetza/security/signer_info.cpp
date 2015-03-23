#include <vanetza/security/signer_info.hpp>
#include <vanetza/security/certificate.hpp>

namespace vanetza
{
namespace security
{

SignerInfoType get_type(const SignerInfo& info) {
    struct SignerInfo_visitor: public boost::static_visitor<>
    {
        void operator()(const HashedId8& id) {
            m_type = SignerInfoType::Certificate_Digest_With_EDCSAP256;
        }
        void operator()(const Certificate& cert) {
            m_type = SignerInfoType::Certificate;
        }
        void operator()(const std::list<Certificate>& list) {
            m_type = SignerInfoType::Certificate_Chain;
        }
        void operator()(const CertificateDigestWithOtherAlgorithm& cert) {
            m_type = SignerInfoType::Certificate_Digest_With_Other_Algorithm;
        }
        SignerInfoType m_type;
    };

    SignerInfo_visitor visit;
    boost::apply_visitor(visit, info);
    return visit.m_type;
}

size_t get_size(const CertificateDigestWithOtherAlgorithm& cert) {
    size_t size = cert.digest.size();
    size += sizeof(cert.algorithm);
    return size;
}

size_t get_size(const SignerInfo& info) {
    struct SignerInfo_visitor: public boost::static_visitor<>
    {
        void operator()(const HashedId8& id) {
            m_size = id.size();
        }
        void operator()(const Certificate& cert) {
            m_size = get_size(cert);
        }
        void operator()(const std::list<Certificate>& list) {
            m_size = get_size(list);
        }
        void operator()(const CertificateDigestWithOtherAlgorithm& cert) {
            m_size = get_size(cert);
        }
        size_t m_size;
    };

    SignerInfo_visitor visit;
    boost::apply_visitor(visit, info);
    return visit.m_size;
}

void serialize(OutputArchive& ar, const std::list<SignerInfo>& list) {
    size_t size = 0;
    for (auto& info : list) {
        size += get_size(info);
    }
    serialize_length(ar, size);
    for (auto& info : list) {
        serialize(ar, info);
    }
}

void serialize(OutputArchive& ar, const CertificateDigestWithOtherAlgorithm& cert) {
    ar << cert.algorithm;
    for (auto& byte : cert.digest) {
        ar << byte;
    }
}

void serialize(OutputArchive& ar, const SignerInfo& info) {
    struct SignerInfo_visitor: public boost::static_visitor<>
    {
        SignerInfo_visitor(OutputArchive& ar) : m_archive(ar) {}

        void operator()(const HashedId8& id) {
            for (auto& byte : id) {
                m_archive << byte;
            }
        }
        void operator()(const Certificate& cert) {
            serialize(m_archive, cert);
        }
        void operator()(const std::list<Certificate>& list) {
            serialize(m_archive, list);
        }
        void operator()(const CertificateDigestWithOtherAlgorithm& cert) {
            serialize(m_archive, cert);
        }
        OutputArchive& m_archive;
    };
    SignerInfoType type = get_type(info);
    ar << type;
    SignerInfo_visitor visit(ar);
    boost::apply_visitor(visit, info);
}

size_t deserialize(InputArchive& ar, CertificateDigestWithOtherAlgorithm& cert) {
    ar >> cert.algorithm;
    for (size_t c = 0; c < 8; c++) {
        ar >> cert.digest[c];
    }
    size_t size = cert.digest.size();
    size += sizeof(cert.algorithm);
    return size;
}

size_t deserialize(InputArchive& ar, std::list<SignerInfo>& list) {
    size_t size = 0;
    size = deserialize_length(ar);
    size_t retSize = size;
    while (size > 0) {
        SignerInfo info;
        size -= deserialize(ar, info);
        list.push_back(info);
    }
    return retSize;
}

size_t deserialize(InputArchive& ar, SignerInfo& info) {
    SignerInfoType type;
    size_t size = 0;
    ar >> type;
    switch (type) {
        case SignerInfoType::Certificate: {
            Certificate cert;
            size += deserialize(ar, cert);
            info = cert;
            break;
        }
        case SignerInfoType::Certificate_Chain: {
            std::list<Certificate> list;
            size += deserialize(ar, list);
            info = list;
            break;
        }
        case SignerInfoType::Certificate_Digest_With_EDCSAP256: {
            HashedId8 cert;
            for (size_t c = 0; c < 8; c++) {
                ar >> cert[c];
            }
            info = cert;
            size = sizeof(cert);
            break;
        }
        case SignerInfoType::Certificate_Digest_With_Other_Algorithm: {
            CertificateDigestWithOtherAlgorithm cert;
            size = deserialize(ar, cert);
            info = cert;
            break;
        }
        case SignerInfoType::Self:
            break;

        default:
            throw deserialization_error("Unknown SignerInfoType");
    }
    return size;
}

} // ns security
} // ns vanetza
