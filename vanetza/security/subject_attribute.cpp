#include <vanetza/security/subject_attribute.hpp>

namespace vanetza
{
namespace security
{

SubjectAttributeType get_type(const SubjectAttribute& sub)
{
    struct subject_attribute_visitor : public boost::static_visitor<SubjectAttributeType>
    {
        SubjectAttributeType operator()(VerificationKey key)
        {
            return SubjectAttributeType::Verification_Key;
        }
        SubjectAttributeType operator()(EncryptionKey key)
        {
            return SubjectAttributeType::Encryption_Key;
        }
        SubjectAttributeType operator()(SubjectAssurance assurance)
        {
            return SubjectAttributeType::Assurance_Level;
        }
        SubjectAttributeType operator()(std::list<IntX> list)
        {
            return SubjectAttributeType::Its_Aid_List;
        }
        SubjectAttributeType operator()(EccPoint ecc)
        {
            return SubjectAttributeType::Reconstruction_Value;
        }
        SubjectAttributeType operator()(std::list<ItsAidSsp> list)
        {
            return SubjectAttributeType::Its_Aid_Ssp_List;
        }
        SubjectAttributeType operator()(std::list<ItsAidPriority> list)
        {
            return SubjectAttributeType::Priority_Its_Aid_List;
        }
        SubjectAttributeType operator()(std::list<ItsAidPrioritySsp> list)
        {
            return SubjectAttributeType::Priority_Ssp_List;
        }
    };

    subject_attribute_visitor visit;
    return boost::apply_visitor(visit, sub);
}

void serialize(OutputArchive& ar, const std::list<IntX>& list)
{
    serialize_length(ar, get_size(list));
    for (auto& x : list) {
        serialize(ar, x);
    }
}

void serialize(OutputArchive& ar, const std::list<ItsAidSsp>& list)
{
    serialize_length(ar, get_size(list));
    for (auto& itsAidSsp : list) {
        serialize(ar, itsAidSsp.its_aid);
        size_t size = itsAidSsp.service_specific_permissions.size();
        serialize_length(ar, size);
        for (auto& byte : itsAidSsp.service_specific_permissions) {
            ar << byte;
        }
    }
}

void serialize(OutputArchive& ar, const std::list<ItsAidPriority>& list)
{
    serialize_length(ar, get_size(list));
    for (auto& itsAidPriority : list) {
        serialize(ar, itsAidPriority.its_aid);
        geonet::serialize(host_cast(itsAidPriority.max_priority), ar);
    }
}

void serialize(OutputArchive& ar, const std::list<ItsAidPrioritySsp>& list)
{
    serialize_length(ar, get_size(list));
    for (auto& itsAidPrioritySsp : list) {
        serialize(ar, itsAidPrioritySsp.its_aid);
        geonet::serialize(host_cast(itsAidPrioritySsp.max_priority), ar);
        size_t size = itsAidPrioritySsp.service_specific_permissions.size();
        serialize_length(ar, size);
        for (auto& byte : itsAidPrioritySsp.service_specific_permissions) {
            ar << byte;
        }
    }
}

size_t deserialize(InputArchive& ar, std::list<IntX>& list)
{
    size_t ret_size = 0;
    ret_size = deserialize_length(ar);
    size_t size = ret_size;
    while (size > 0) {
        IntX x;
        deserialize(ar, x);
        size -= get_size(x);
        list.push_back(x);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, std::list<ItsAidSsp>& list)
{
    size_t size = 0;
    size_t ret_size = deserialize_length(ar);
    size = ret_size;
    while (size > 0) {
        ItsAidSsp ssp;
        deserialize(ar, ssp.its_aid);
        size -= get_size(ssp.its_aid);
        size_t buf_size = deserialize_length(ar);
        size -= buf_size;
        uint8_t uint;
        size -= length_coding_size(buf_size);
        for (; buf_size > 0; buf_size--) {
            ar >> uint;
            ssp.service_specific_permissions.push_back(uint);
        }
        list.push_back(ssp);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, std::list<ItsAidPriority>& list)
{
    size_t size = 0;
    size_t ret_size = deserialize_length(ar);
    size = ret_size;
    while (size > 0) {
        ItsAidPriority aid;
        deserialize(ar, aid.its_aid);
        size -= get_size(aid.its_aid);
        geonet::deserialize(aid.max_priority, ar);
        size -= sizeof(uint8_t);
        list.push_back(aid);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, std::list<ItsAidPrioritySsp>& list)
{
    size_t ret_size = deserialize_length(ar);
    size_t size = ret_size;
    while (size > 0) {
        ItsAidPrioritySsp aid;
        deserialize(ar, aid.its_aid);
        size -= get_size(aid.its_aid);
        geonet::deserialize(aid.max_priority, ar);
        size -= sizeof(uint8_t);
        size_t buf_size = deserialize_length(ar);
        size -= buf_size;
        uint8_t uint;
        size -= length_coding_size(buf_size);
        for (; buf_size > 0; buf_size--) {
            ar >> uint;
            aid.service_specific_permissions.push_back(uint);
        }
        list.push_back(aid);
    }
    return ret_size;
}

size_t get_size(const std::list<IntX>& list)
{
    size_t size = 0;
    for (auto& x : list) {
        size += get_size(x);
    }
    return size;
}

size_t get_size(const SubjectAssurance& assurance)
{
    return sizeof(uint8_t);
}

size_t get_size(const std::list<ItsAidSsp>& list)
{
    size_t size = 0;
    for (auto& itsAidSsp : list) {
        size += get_size(itsAidSsp.its_aid);
        size += itsAidSsp.service_specific_permissions.size();
        size += length_coding_size(itsAidSsp.service_specific_permissions.size());
    }
    return size;
}

size_t get_size(const std::list<ItsAidPriority>& list)
{
    size_t size = 0;
    for (auto& itsAidPriority : list) {
        size += get_size(itsAidPriority.its_aid);
        size += sizeof(uint8_t);
    }
    return size;
}

size_t get_size(const std::list<ItsAidPrioritySsp>& list)
{
    size_t size = 0;
    for (auto& itsAidPrioritySssp : list) {
        size += get_size(itsAidPrioritySssp.its_aid);
        size += sizeof(uint8_t);
        size += itsAidPrioritySssp.service_specific_permissions.size();
        size += length_coding_size(itsAidPrioritySssp.service_specific_permissions.size());
    }
    return size;
}

size_t get_size(const SubjectAttribute& sub)
{
    size_t size = sizeof(SubjectAttributeType);
    struct subject_attribute_visitor : public boost::static_visitor<size_t>
    {
        size_t operator()(VerificationKey key)
        {
            return get_size(key.key);
        }
        size_t operator()(EncryptionKey key)
        {
            return get_size(key.key);
        }
        size_t operator()(SubjectAssurance assurance)
        {
            return get_size(assurance);
        }
        size_t operator()(std::list<IntX> list)
        {
            size_t size = get_size(list);
            size += length_coding_size(size);
            return size;
        }
        size_t operator()(EccPoint ecc)
        {
            return get_size(ecc);
        }
        size_t operator()(std::list<ItsAidSsp> list)
        {
            size_t size = get_size(list);
            size += length_coding_size(size);
            return size;
        }
        size_t operator()(std::list<ItsAidPriority> list)
        {
            size_t size = get_size(list);
            size += length_coding_size(size);
            return size;
        }
        size_t operator()(std::list<ItsAidPrioritySsp> list)
        {
            size_t size = get_size(list);
            size += length_coding_size(size);
            return size;
        }
    };

    subject_attribute_visitor visit;
    size += boost::apply_visitor(visit, sub);
    return size;
}

void serialize(OutputArchive& ar, const SubjectAttribute& subjectAttribute)
{
    struct subject_attribute_visitor : public boost::static_visitor<>
    {
        subject_attribute_visitor(OutputArchive& ar) :
            m_archive(ar)
        {
        }
        void operator()(VerificationKey key)
        {
            serialize(m_archive, key.key);
        }
        void operator()(EncryptionKey key)
        {
            serialize(m_archive, key.key);
        }
        void operator()(SubjectAssurance assurance)
        {
            m_archive << assurance;
        }
        void operator()(std::list<IntX> list)
        {
            serialize(m_archive, list);
        }
        void operator()(EccPoint ecc)
        {
        }
        void operator()(std::list<ItsAidSsp> list)
        {
            serialize(m_archive, list);
        }
        void operator()(std::list<ItsAidPriority> list)
        {
            serialize(m_archive, list);
        }
        void operator()(std::list<ItsAidPrioritySsp> list)
        {
            serialize(m_archive, list);
        }
        OutputArchive& m_archive;
    };

    SubjectAttributeType type = get_type(subjectAttribute);
    serialize(ar, type);
    subject_attribute_visitor visit(ar);
    boost::apply_visitor(visit, subjectAttribute);
}

size_t deserialize(InputArchive& ar, SubjectAttribute& sub)
{
    SubjectAttributeType type;
    size_t size = 0;
    deserialize(ar, type);
    size += sizeof(type);
    switch (type) {
        case SubjectAttributeType::Assurance_Level: {
            SubjectAssurance assurance;
            ar >> assurance;
            size += get_size(assurance);
            sub = assurance;
            break;
        }
        case SubjectAttributeType::Verification_Key: {
            VerificationKey key;
            size += deserialize(ar, key.key);
            sub = key;
            break;
        }
        case SubjectAttributeType::Encryption_Key: {
            EncryptionKey key;
            size += deserialize(ar, key.key);
            sub = key;
            break;
        }
        case SubjectAttributeType::Its_Aid_List: {
            std::list<IntX> intx_list;
            size_t tmp_size = deserialize(ar, intx_list);
            size += tmp_size;
            size += length_coding_size(tmp_size);
            sub = intx_list;
            break;
        }
        case SubjectAttributeType::Its_Aid_Ssp_List: {
            std::list<ItsAidSsp> itsAidSsp_list;
            size_t tmp_size = deserialize(ar, itsAidSsp_list);
            size += tmp_size;
            size += length_coding_size(tmp_size);
            sub = itsAidSsp_list;
            break;
        }
        case SubjectAttributeType::Priority_Its_Aid_List: {
            std::list<ItsAidPriority> itsAidPriority_list;
            size_t tmp_size = deserialize(ar, itsAidPriority_list);
            size += tmp_size;
            size += length_coding_size(tmp_size);
            sub = itsAidPriority_list;
            break;
        }
        case SubjectAttributeType::Reconstruction_Value:
            break;
        case SubjectAttributeType::Priority_Ssp_List: {
            std::list<ItsAidPrioritySsp> itsAidPrioritySsp_list;
            size_t tmp_size = deserialize(ar, itsAidPrioritySsp_list);
            size += tmp_size;
            size += length_coding_size(tmp_size);
            sub = itsAidPrioritySsp_list;
            break;
        }
        default:
            throw deserialization_error("Unknown SubjectAttributeType");
    }

    return size;
}

} //namespace security
} //namespace vanetza
