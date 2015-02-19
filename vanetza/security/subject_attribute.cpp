#include <vanetza/security/subject_attribute.hpp>

namespace vanetza {
namespace security {

SubjectAttributeType get_type(const SubjectAttribute& sub) {
    struct subject_attribute_visitor: public boost::static_visitor<> {
        void operator()(VerificationKey key) {
            m_type = SubjectAttributeType::Verification_Key;
        }
        void operator()(EncryptionKey key) {
            m_type = SubjectAttributeType::Encryption_Key;
        }
        void operator()(SubjectAssurance assurance) {
            m_type = SubjectAttributeType::Assurance_Level;
        }
        void operator()(std::list<IntX> list) {
            m_type = SubjectAttributeType::Its_Aid_List;
        }
        void operator()(EccPoint ecc) {}
        void operator()(std::list<ItsAidSsp> list) {
            m_type = SubjectAttributeType::Its_Aid_Ssp_List;
        }
        void operator()(std::list<ItsAidPriority> list) {
            m_type = SubjectAttributeType::Priority_Its_Aid_List;
        }
        void operator()(std::list<ItsAidPrioritySsp> list) {
            m_type = SubjectAttributeType::Priority_Ssp_List;
        }
        SubjectAttributeType m_type;
    };

    subject_attribute_visitor visit;
    boost::apply_visitor(visit, sub);
    return visit.m_type;
}

void serialize(OutputArchive& ar, const std::list<IntX>& list) {
    for (auto& x : list) {
        serialize(ar, x);
    }
}

void serialize(OutputArchive& ar, const std::list<ItsAidSsp>& list) {
    for (auto& itsAidSsp : list) {
        serialize(ar, itsAidSsp.its_aid);
        size_t size = itsAidSsp.service_specific_permissions.size();
        serialize_length(ar, size);
        for (auto& byte : itsAidSsp.service_specific_permissions) {
            ar << byte;
        }
    }
}

void serialize(OutputArchive& ar, const std::list<ItsAidPriority>& list) {
    for (auto& itsAidPriority : list) {
        serialize(ar, itsAidPriority.its_aid);
        geonet::serialize(host_cast(itsAidPriority.max_priority), ar);
    }
}

void serialize(OutputArchive& ar, const std::list<ItsAidPrioritySsp>& list) {
    for (auto& itsAidPrioritySsp : list) {
        serialize(ar, itsAidPrioritySsp.its_aid);
        geonet::serialize(host_cast(itsAidPrioritySsp.max_priority), ar);
        serialize_length(ar, itsAidPrioritySsp.service_specific_permissions.size());
        for (auto& byte : itsAidPrioritySsp.service_specific_permissions) {
            ar << byte;
        }
    }
}

size_t deserialize(InputArchive& ar, std::list<IntX>& list) {
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

size_t deserialize(InputArchive& ar, std::list<ItsAidSsp>& list) {
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
        for (; buf_size > 0; buf_size--) {
            ar >> uint;
            ssp.service_specific_permissions.push_back(uint);
        }
        list.push_back(ssp);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, std::list<ItsAidPriority>& list) {
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

size_t deserialize(InputArchive& ar, std::list<ItsAidPrioritySsp>& list) {
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
        for (; buf_size > 0; buf_size--) {
            ar >> uint;
            aid.service_specific_permissions.push_back(uint);
        }
        list.push_back(aid);
    }
    return ret_size;
}

size_t get_size(const std::list<IntX>& list) {
    size_t size = 0;
    for (auto& x : list) {
        size += get_size(x);
    }
    return size;
}

size_t get_size(const SubjectAssurance& assurance) {
    return sizeof(uint8_t);
}

size_t get_size(const std::list<ItsAidSsp>& list) {
    size_t size = 0;
    for (auto& itsAidSsp : list) {
        size += get_size(itsAidSsp.its_aid);
        size += itsAidSsp.service_specific_permissions.size();
    }
    return size;
}

size_t get_size(const std::list<ItsAidPriority>& list) {
    size_t size = 0;
    for (auto& itsAidPriority : list) {
        size += get_size(itsAidPriority.its_aid);
        size += sizeof(uint8_t);
    }
    return size;
}

size_t get_size(const std::list<ItsAidPrioritySsp>& list) {
    size_t size = 0;
    for (auto& itsAidPrioritySssp : list) {
        size += get_size(itsAidPrioritySssp.its_aid);
        size += sizeof(uint8_t);
        size += itsAidPrioritySssp.service_specific_permissions.size();
    }
    return size;
}

size_t get_size(const SubjectAttribute& sub) {
    size_t size = 0;
    SubjectAttributeType type = get_type(sub);
    switch (type) {
    case SubjectAttributeType::Assurance_Level:
        size = get_size(boost::get<SubjectAssurance>(sub));
        break;
    case SubjectAttributeType::Encryption_Key:
        size = get_size(boost::get<EncryptionKey>(sub).key);
        break;
    case SubjectAttributeType::Its_Aid_List:
        size = get_size(boost::get<std::list<IntX>>(sub));
        break;
    case SubjectAttributeType::Its_Aid_Ssp_List:
        size = get_size(boost::get<std::list<ItsAidSsp> >(sub));
        break;
    case SubjectAttributeType::Priority_Its_Aid_List:
        size = get_size(boost::get<std::list<ItsAidPriority> >(sub));
        break;
    case SubjectAttributeType::Reconstruction_Value:
        size = get_size(boost::get<EccPoint>(sub));
        break;
    case SubjectAttributeType::Verification_Key:
        size = get_size(boost::get<VerificationKey>(sub).key);

        break;
    case SubjectAttributeType::Priority_Ssp_List:
        size = get_size(boost::get<std::list<ItsAidPrioritySsp>>(sub));
        break;
    }
    return size;
}

void serialize(OutputArchive& ar, const std::list<SubjectAttribute>& list) {
    size_t size = 0;
    for (auto& subjectAttribute : list) {
        size += get_size(subjectAttribute);
    }
    serialize_length(ar, int(size));

    for (auto& subjectAttribute : list) {
        struct subject_attribute_visitor: public boost::static_visitor<> {
            subject_attribute_visitor(OutputArchive& ar) :
                    m_archive(ar){
            }
            void operator()(VerificationKey key) {
                serialize(m_archive, key.key);
            }
            void operator()(EncryptionKey key) {
                serialize(m_archive, key.key);
            }
            void operator()(SubjectAssurance assurance) {
                m_archive << assurance;
            }
            void operator()(std::list<IntX> list) {
                serialize_length(m_archive, get_size(list));
                serialize(m_archive, list);
            }
            void operator()(EccPoint ecc) {}
            void operator()(std::list<ItsAidSsp> list) {
                serialize_length(m_archive, get_size(list));
                serialize(m_archive, list);
            }
            void operator()(std::list<ItsAidPriority> list) {
                serialize_length(m_archive, get_size(list));
                serialize(m_archive, list);
            }
            void operator()(std::list<ItsAidPrioritySsp> list) {
                serialize_length(m_archive, get_size(list));
                serialize(m_archive, list);
            }
            OutputArchive& m_archive;
        };

        SubjectAttributeType type = get_type(subjectAttribute);
        ar << type;
        subject_attribute_visitor visit(ar);
        boost::apply_visitor(visit, subjectAttribute);
    }
}

size_t deserialize(InputArchive& ar, std::list<SubjectAttribute>& list) {
    SubjectAttributeType type;
    size_t size = deserialize_length(ar);
    size_t ret_size = size;

    while (size > 0) {
        ar >> type;
        switch (type) {
        case SubjectAttributeType::Assurance_Level: {
            SubjectAssurance assurance;
            ar >> assurance;
            size -= get_size(assurance);
            SubjectAttribute sub = assurance;
            list.push_back(sub);
            break;
        }
        case SubjectAttributeType::Verification_Key: {
            VerificationKey key;
            size -= deserialize(ar, key.key);
            SubjectAttribute sub = key;
            list.push_back(sub);
            break;
        }
        case SubjectAttributeType::Encryption_Key: {
            EncryptionKey key;
            size -= deserialize(ar, key.key);
            SubjectAttribute sub = key;
            list.push_back(sub);
            break;
        }
        case SubjectAttributeType::Its_Aid_List: {
            std::list<IntX> intx_list;
            size -= deserialize(ar, intx_list);
            SubjectAttribute sub = intx_list;
            list.push_back(sub);
            break;
        }
        case SubjectAttributeType::Its_Aid_Ssp_List: {
            std::list<ItsAidSsp> itsAidSsp_list;
            size -= deserialize(ar, itsAidSsp_list);
            SubjectAttribute sub = itsAidSsp_list;
            list.push_back(sub);
            break;
        }
        case SubjectAttributeType::Priority_Its_Aid_List: {
            std::list<ItsAidPriority> itsAidPriority_list;
            size -= deserialize(ar, itsAidPriority_list);
            SubjectAttribute sub = itsAidPriority_list;
            list.push_back(sub);
            break;
        }
        case SubjectAttributeType::Reconstruction_Value:
            break;
        case SubjectAttributeType::Priority_Ssp_List: {
            std::list<ItsAidPrioritySsp> itsAidPrioritySsp_list;
            size -= deserialize(ar, itsAidPrioritySsp_list);
            SubjectAttribute sub = itsAidPrioritySsp_list;
            list.push_back(sub);
            break;
        }
        default:
            throw deserialization_error("Unknown SubjectAttributeType");
    }
    }
    return ret_size;
}

} //namespace security
} //namespace vanetza
