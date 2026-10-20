#include <vanetza/asn1/asn1c_error.hpp>
#include <vanetza/asn1/support/constr_TYPE.h>
#include <string>
#include <type_traits>

namespace vanetza
{
namespace asn1
{

static_assert(std::is_trivially_copyable<asn1c_error>::value, "asn1c_error must remain trivially copyable");

namespace
{

const char* code_description(ErrorCode code)
{
    switch (code) {
        case ErrorCode::Ok:
            return "no error";
        case ErrorCode::EncodeFailed:
            return "ASN.1 encoding failed";
        case ErrorCode::DecodeIncomplete:
            return "ASN.1 decoding incomplete";
        case ErrorCode::DecodeFailed:
            return "ASN.1 decoding failed";
        case ErrorCode::OutOfMemory:
            return "out of memory";
    }
    return "unknown ASN.1 error";
}

std::string make_message(const asn1c_error& err)
{
    std::string msg = code_description(err.code());
    const std::string root = err.root_type_name();
    const std::string failed = err.failed_type_name();
    if (!root.empty()) {
        msg += " (type: " + root + ")";
    }
    if (!failed.empty()) {
        msg += " (failed at: " + failed + ")";
    }
    return msg;
}

} // namespace

asn1c_error::asn1c_error(
    ErrorCode code, const asn_TYPE_descriptor_s* root_type, const asn_TYPE_descriptor_s* failed_type) noexcept :
    m_code(code), m_root_type(root_type), m_failed_type(failed_type)
{
}

const char* asn1c_error::root_type_name() const noexcept
{
    return m_root_type && m_root_type->name ? m_root_type->name : "";
}

const char* asn1c_error::failed_type_name() const noexcept
{
    return m_failed_type && m_failed_type->name ? m_failed_type->name : "";
}

asn1c_exception::asn1c_exception(const asn1c_error& err) : std::runtime_error(make_message(err)), m_error(err) {}

} // namespace asn1
} // namespace vanetza
