#include <vanetza/security/certificate.hpp>
#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/signer_info.hpp>

namespace vanetza
{
namespace security
{

size_t get_size(const Certificate& cert)
{
    size_t size = sizeof(cert.version);
    size += get_size(cert.signer_info);
    size += length_coding_size(get_size(cert.signer_info));
    size += get_size(cert.subject_info);
    size += get_size(cert.subject_attributes);
    size += length_coding_size(get_size(cert.subject_attributes));
    size += get_size(cert.validity_restriction);
    size += length_coding_size(get_size(cert.validity_restriction));
    size += get_size(cert.signature);
    return size;
}


void serialize(OutputArchive& ar, const Certificate& cert)
{
    geonet::serialize(host_cast(cert.version), ar);
    serialize(ar, cert.signer_info);
    serialize(ar, cert.subject_info);
    serialize(ar, cert.subject_attributes);
    serialize(ar, cert.validity_restriction);
    serialize(ar, cert.signature);
}

size_t deserialize(InputArchive& ar, Certificate& cert)
{
    geonet::deserialize(cert.version, ar);
    size_t size = sizeof(cert.version);
    size += deserialize(ar, cert.signer_info);
    size += length_coding_size(get_size(cert.signer_info));
    size += deserialize(ar, cert.subject_info);
    size += deserialize(ar, cert.subject_attributes);
    size += length_coding_size(get_size(cert.subject_attributes));
    size += deserialize(ar, cert.validity_restriction);
    size += length_coding_size(get_size(cert.validity_restriction));
    size += deserialize(ar, cert.signature);
    return size;
}

} // ns security
} // ns vanetza

