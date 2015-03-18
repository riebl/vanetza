#include <vanetza/security/subject_info.hpp>
#include <vanetza/security/length_coding.hpp>

namespace vanetza
{
namespace security
{

size_t get_size(const SubjectInfo& sub) {
    size_t size = sizeof(sub.subject_type);
    size += sub.subject_name.size();
    return size;
}

void serialize(OutputArchive& ar, const SubjectInfo& sub) {
    ar << sub.subject_type;
    size_t size = sub.subject_name.size();
    size += sizeof(sub.subject_type);
    serialize_length(ar, size);
    for (auto& byte : sub.subject_name) {
        ar << byte;
    }
}

size_t deserialize(InputArchive& ar, SubjectInfo& sub) {
    ar >> sub.subject_type;
    size_t size = deserialize_length(ar);
    size_t ret_size = size;
    size -= sizeof(sub.subject_type);
    for (int c = 0; c < size; c++) {
        uint8_t tmp;
        ar >> tmp;
        sub.subject_name.push_back(tmp);
    }
    return ret_size;
}

} // ns security
} // ns vanetza

