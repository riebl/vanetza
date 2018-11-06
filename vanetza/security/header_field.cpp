#include <vanetza/security/exception.hpp>
#include <vanetza/security/header_field.hpp>
#include <boost/optional.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace security
{

HeaderFieldType get_type(const HeaderField& field)
{
    struct HeaderFieldVisitor : public boost::static_visitor<HeaderFieldType>
    {
        HeaderFieldType operator()(const Time64&)
        {
            return HeaderFieldType::Generation_Time;
        }
        HeaderFieldType operator()(const Time64WithStandardDeviation&)
        {
            return HeaderFieldType::Generation_Time_Confidence;
        }
        HeaderFieldType operator()(const Time32&)
        {
            return HeaderFieldType::Expiration;
        }
        HeaderFieldType operator()(const ThreeDLocation&)
        {
            return HeaderFieldType::Generation_Location;
        }
        HeaderFieldType operator()(const std::list<HashedId3>&)
        {
            return HeaderFieldType::Request_Unrecognized_Certificate;
        }
        HeaderFieldType operator()(const IntX&)
        {
            return HeaderFieldType::Its_Aid;
        }
        HeaderFieldType operator()(const SignerInfo&)
        {
            return HeaderFieldType::Signer_Info;
        }
        HeaderFieldType operator()(const std::list<RecipientInfo>&)
        {
            return HeaderFieldType::Recipient_Info;
        }
        HeaderFieldType operator()(const EncryptionParameter&)
        {
            return HeaderFieldType::Encryption_Parameters;
        }
    };

    HeaderFieldVisitor visit;
    return boost::apply_visitor(visit, field);
}

size_t get_size(const HeaderField& field)
{
    size_t size = sizeof(HeaderFieldType);
    struct HeaderFieldVisitor : public boost::static_visitor<>
    {
        void operator()(const Time64&)
        {
            m_size = sizeof(Time64);
        }
        void operator()(const Time64WithStandardDeviation& time)
        {
            m_size = sizeof(time.time64);
            m_size += sizeof(time.log_std_dev);
        }
        void operator()(const Time32&)
        {
            m_size = sizeof(Time32);
        }
        void operator()(const ThreeDLocation& loc)
        {
            m_size = get_size(loc);
        }
        void operator()(const std::list<HashedId3>& list)
        {
            m_size = 0;
            for (auto& elem : list) {
                m_size += elem.size();
            }
            m_size += length_coding_size(m_size);
        }
        void operator()(const IntX& itsAid)
        {
            m_size = get_size(itsAid);
        }
        void operator()(const SignerInfo& info)
        {
            m_size = get_size(info);
        }
        void operator()(const std::list<RecipientInfo>& list)
        {
            m_size = get_size(list);
            m_size += length_coding_size(m_size);
        }
        void operator()(const EncryptionParameter& enc)
        {
            m_size = get_size(enc);
        }
        size_t m_size;
    };

    HeaderFieldVisitor visit;
    boost::apply_visitor(visit, field);
    size += visit.m_size;
    return size;
}

void serialize(OutputArchive& ar, const HeaderField& field)
{
    struct HeaderFieldVisitor : public boost::static_visitor<>
    {
        HeaderFieldVisitor(OutputArchive& ar) :
            m_archive(ar)
        {
        }
        void operator()(const Time64& time)
        {
            serialize(m_archive, host_cast(time));
        }
        void operator()(const Time64WithStandardDeviation& time)
        {
            serialize(m_archive, host_cast(time.time64));
            serialize(m_archive, host_cast(time.log_std_dev));
        }
        void operator()(const Time32& time)
        {
            serialize(m_archive, host_cast(time));
        }
        void operator()(const ThreeDLocation& loc)
        {
            serialize(m_archive, loc);
        }
        void operator()(const std::list<HashedId3>& list)
        {
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
        void operator()(const IntX& itsAid)
        {
            serialize(m_archive, itsAid);
        }
        void operator()(const SignerInfo& info)
        {
            serialize(m_archive, info);
        }
        void operator()(const std::list<RecipientInfo>& list)
        {
            // TODO: only works until further symmetric algorithms are introduced
            serialize(m_archive, list, SymmetricAlgorithm::AES128_CCM);
        }
        void operator()(const EncryptionParameter& param)
        {
            serialize(m_archive, param);
        }

        OutputArchive& m_archive;
    };
    HeaderFieldType type = get_type(field);
    serialize(ar, type);
    HeaderFieldVisitor visit(ar);
    boost::apply_visitor(visit, field);
}

std::size_t deserialize(InputArchive& ar, std::list<HeaderField>& list)
{
    const std::size_t size = trim_size(deserialize_length(ar));
    std::size_t read = 0;
    boost::optional<SymmetricAlgorithm> sym_algo;
    while (read < size) {
        HeaderField field;
        HeaderFieldType type;
        deserialize(ar, type);
        read += sizeof(HeaderFieldType);
        switch (type) {
            case HeaderFieldType::Generation_Time: {
                Time64 time;
                deserialize(ar, time);
                field = time;
                list.push_back(field);
                read += sizeof(Time64);
                break;
            }
            case HeaderFieldType::Generation_Time_Confidence: {
                Time64WithStandardDeviation time;
                deserialize(ar, time.time64);
                deserialize(ar, time.log_std_dev);
                field = time;
                list.push_back(field);
                read += sizeof(Time64);
                read += sizeof(uint8_t);
                break;
            }
            case HeaderFieldType::Expiration: {
                Time32 time;
                deserialize(ar, time);
                field = time;
                list.push_back(field);
                read += sizeof(Time32);
                break;
            }
            case HeaderFieldType::Generation_Location: {
                ThreeDLocation loc;
                read += deserialize(ar, loc);
                field = loc;
                list.push_back(field);
                break;
            }
            case HeaderFieldType::Request_Unrecognized_Certificate: {
                const std::size_t tmp_size = trim_size(deserialize_length(ar));
                read += tmp_size;
                std::list<HashedId3> hashedList;
                for (std::size_t c = 0; c < tmp_size; c += 3) {
                    HashedId3 id;
                    ar >> id[0];
                    ar >> id[1];
                    ar >> id[2];
                    hashedList.push_back(id);
                }
                field = hashedList;
                read += length_coding_size(tmp_size);
                list.push_back(field);
                break;
            }
            case HeaderFieldType::Its_Aid: {
                IntX its_aid;
                read += deserialize(ar, its_aid);
                field = its_aid;
                list.push_back(field);
                break;
            }
            case HeaderFieldType::Signer_Info: {
                SignerInfo info;
                read += deserialize(ar, info);
                field = info;
                list.push_back(field);
                break;
            }
            case HeaderFieldType::Recipient_Info: {
                std::list<RecipientInfo> recipientList;
                if (sym_algo) {
                    const size_t tmp_size = deserialize(ar, recipientList, sym_algo.get());
                    read += tmp_size;
                    read += length_coding_size(tmp_size);
                    field = recipientList;
                    list.push_back(field);
                } else {
                    throw deserialization_error("HeaderFields: RecipientInfo read before EncryptionParameters: SymmetricAlgorithm still unknown");
                }
                break;
            }
            case HeaderFieldType::Encryption_Parameters: {
                EncryptionParameter param;
                read += deserialize(ar, param);
                field = param;
                sym_algo = get_type(param);
                list.push_back(field);
                break;
            }
            default:
                throw deserialization_error("Unknown HeaderFieldType");
                break;
        }
    }
    return size;
}

} // namespace security
} // namespace vanetza
