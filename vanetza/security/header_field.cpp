#include <vanetza/security/certificate.hpp>
#include <vanetza/security/header_field.hpp>
#include <string>
#include <sstream>
#include <memory>

using namespace std;

namespace vanetza
{
namespace security
{

HeaderFieldType get_type(const HeaderField& field) {
    struct HeaderFieldVisitor: public boost::static_visitor<>
    {
        void operator()(const Time64& time) {
            m_type = HeaderFieldType::Generation_Time;
        }
        void operator()(const Time64WithStandardDeviation& time) {
            m_type = HeaderFieldType::Generation_Time_Confidence;
        }
        void operator()(const Time32& time) {
            m_type = HeaderFieldType::Expiration;
        }
        void operator()(const ThreeDLocation& time) {
            m_type = HeaderFieldType::Generation_Location;
        }
        void operator()(const std::list<HashedId3>& digest) {
            m_type = HeaderFieldType::Request_Unrecognized_Certificate;
        }
        void operator()(const uint16_t& msgType) {
            m_type = HeaderFieldType::Message_Type;
        }
        void operator()(const SignerInfo& info) {
            m_type = HeaderFieldType::Signer_Info;
        }
        void operator()(const std::list<RecipientInfo>& list) {
            m_type = HeaderFieldType::Recipient_Info;
        }
        void operator()(const EncryptionParameter& param) {
            m_type = HeaderFieldType::Encryption_Parameters;
        }
        HeaderFieldType m_type;
    };

    HeaderFieldVisitor visit;
    boost::apply_visitor(visit, field);
    return visit.m_type;
}

size_t get_size(const HeaderField& field) {
    struct HeaderFieldVisitor: public boost::static_visitor<>
    {
        void operator()(const Time64& time) {
            m_size = sizeof(Time64);
        }
        void operator()(const Time64WithStandardDeviation& time) {
            m_size = sizeof(time.time64);
            m_size += sizeof(time.log_std_dev);
        }
        void operator()(const Time32& time) {
            m_size = sizeof(Time32);
        }
        void operator()(const ThreeDLocation& loc) {
            m_size = get_size(loc);
        }
        void operator()(const std::list<HashedId3>& list) {
            m_size = 0;
            for (auto& elem : list) {
                m_size += elem.size();
            }
            m_size += get_length_coding_size(m_size);
        }
        void operator()(const uint16_t& msgType) {
            m_size = sizeof(uint16_t);
        }
        void operator()(const SignerInfo& info) {
            m_size = get_size(info);
        }
        void operator()(const std::list<RecipientInfo>& list) {
            m_size = get_size(list);
            m_size += get_length_coding_size(m_size);
        }
        void operator()(const EncryptionParameter& enc) {
            m_size = get_size(enc);
        }
        size_t m_size;
    };

    HeaderFieldVisitor visit;
    boost::apply_visitor(visit, field);
    return visit.m_size;
}

size_t get_size(const std::list<HeaderField>& list) {
    size_t size = 0;
    for (auto& field : list) {
        size += get_size(field);
        size += sizeof(HeaderFieldType);
    }
    return size;
}

void serialize(OutputArchive& ar, const std::list<HeaderField>& list) {
    serialize_length(ar, get_size(list));
    for (auto& field : list) {
        serialize(ar, field);
    }
}

void serialize(OutputArchive& ar, const HeaderField& field) {
    struct HeaderFieldVisitor: public boost::static_visitor<>
    {
        HeaderFieldVisitor(OutputArchive& ar) :
                m_archive(ar) {
        }
        void operator()(const Time64& time) {
            geonet::serialize(host_cast(time), m_archive);
        }
        void operator()(const Time64WithStandardDeviation& time) {
            geonet::serialize(host_cast(time.time64), m_archive);
            geonet::serialize(host_cast(time.log_std_dev), m_archive);
        }
        void operator()(const Time32& time) {
            geonet::serialize(host_cast(time), m_archive);
        }
        void operator()(const ThreeDLocation& loc) {
            serialize(m_archive, loc);
        }
        void operator()(const std::list<HashedId3>& list) {
            size_t size = 0;
            for (auto& elem : list) {
                size += elem.size();
            }
            serialize_length(m_archive, size);
            for (auto& elem : list) {
                m_archive << elem[0];
                m_archive << elem[1];
                m_archive << elem[2];
            }
        }
        void operator()(const uint16_t& msg_type) {
            geonet::serialize(host_cast(msg_type), m_archive);
        }
        void operator()(const SignerInfo& info) {
            serialize(m_archive, info);
        }
        void operator()(const std::list<RecipientInfo>& list) {
            serialize(m_archive, list);
        }
        void operator()(const EncryptionParameter& param) {
            serialize(m_archive, param);
        }
        OutputArchive& m_archive;
    };
    HeaderFieldType type = get_type(field);
    ar << type;
    HeaderFieldVisitor visit(ar);
    boost::apply_visitor(visit, field);
}

size_t deserialize(InputArchive& ar, std::list<HeaderField>& list) {
    size_t size = deserialize_length(ar);
    SymmetricAlgorithm sym = static_cast<SymmetricAlgorithm>(255);
    size_t ret_size = size;
    while (size > 0) {
        HeaderField field;
        HeaderFieldType type;
        ar >> type;
        switch (type) {
            case HeaderFieldType::Generation_Time: {
                Time64 time;
                geonet::deserialize(time, ar);
                field = time;
                list.push_back(field);
                size -= sizeof(Time64);
                break;
            }
            case HeaderFieldType::Generation_Time_Confidence: {
                Time64WithStandardDeviation time;
                geonet::deserialize(time.time64, ar);
                geonet::deserialize(time.log_std_dev, ar);
                field = time;
                list.push_back(field);
                size -= sizeof(Time64);
                size -= sizeof(uint8_t);
                break;
            }
            case HeaderFieldType::Expiration: {
                Time32 time;
                geonet::deserialize(time, ar);
                field = time;
                list.push_back(field);
                size -= sizeof(Time32);
                break;
            }
            case HeaderFieldType::Generation_Location: {
                ThreeDLocation loc;
                size -= deserialize(ar, loc);
                field = loc;
                list.push_back(field);
                break;
            }
            case HeaderFieldType::Request_Unrecognized_Certificate: {
                size_t tmp_size = deserialize_length(ar);
                size -= tmp_size;
                std::list<HashedId3> hashedList;
                for (size_t c = 0; c < tmp_size; c += 3) {
                    HashedId3 id;
                    ar >> id[0];
                    ar >> id[1];
                    ar >> id[2];
                    hashedList.push_back(id);
                }
                field = hashedList;
                size -= get_length_coding_size(tmp_size);
                list.push_back(field);
                break;
            }
            case HeaderFieldType::Message_Type: {
                uint16_t uint;
                geonet::deserialize(uint, ar);
                field = uint;
                list.push_back(field);
                size -= sizeof(uint16_t);
                break;
            }
            case HeaderFieldType::Signer_Info: {
                SignerInfo info;
                size -= deserialize(ar, info);
                field = info;
                list.push_back(field);
                break;
            }
            case HeaderFieldType::Recipient_Info: {
                std::list<RecipientInfo> recipientList;
                size_t tmp_size = deserialize(ar, recipientList, sym);
                size -= tmp_size;
                size -= get_length_coding_size(tmp_size);
                field = recipientList;
                list.push_back(field);
                break;
            }
            case HeaderFieldType::Encryption_Parameters: {
                EncryptionParameter param;
                size -= deserialize(ar, param, sym);
                field = param;
                list.push_back(field);
                break;
            }
            default:
                throw deserialization_error("Unknown HeaderFieldType");
        }
        size -= sizeof(HeaderFieldType);
    }
    return ret_size;
}

} // namespace security
} // namespace vanextza
