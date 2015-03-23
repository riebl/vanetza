#include <vanetza/security/certificate.hpp>
#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/signer_info.hpp>

namespace vanetza
{
namespace security
{

size_t get_size(const Certificate& cert) {
    size_t size = sizeof(cert.version);
    for (auto& info : cert.signer_info) {
        size += get_size(info);
    }
    size += get_size(cert.subject_info);
    for (auto& attribute : cert.subject_attributes) {
        size += get_size(attribute);
    }
    for (auto& restriction : cert.validity_restriction) {
        size += get_size(restriction);
    }
    size += get_size(cert.signature);
    return size;
}

size_t get_size(const std::list<Certificate>& list) {
    size_t size = 0;
    for (auto& cert : list) {
        size += get_size(cert);
    }
    return size;
}

void serialize(OutputArchive& ar, const std::list<Certificate>& list) {
    size_t size = get_size(list);
    serialize_length(ar, size);
    for (auto& cert : list) {
        serialize(ar, cert);
    }
}

void serialize(OutputArchive& ar, const Certificate& cert) {
    geonet::serialize(host_cast(cert.version), ar);
    serialize(ar, cert.signer_info);
    serialize(ar, cert.subject_info);
    serialize(ar, cert.subject_attributes);
    serialize(ar, cert.validity_restriction);
    serialize(ar, cert.signature);
}

size_t deserialize(InputArchive& ar, std::list<Certificate>& list) {
    size_t size = deserialize_length(ar);
    size_t ret_size = size;
    while (size > 0) {
        Certificate cert;
        size -= deserialize(ar, cert);
        list.push_back(cert);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, Certificate& cert) {
    geonet::deserialize(cert.version, ar);
    size_t size = sizeof(cert.version);
    size += deserialize(ar, cert.signer_info);
    size += deserialize(ar, cert.subject_info);
    size += deserialize(ar, cert.subject_attributes);
    size += deserialize(ar, cert.validity_restriction);
    size += deserialize(ar, cert.signature);
    return size;
}

} // ns security
} // ns vanetza

