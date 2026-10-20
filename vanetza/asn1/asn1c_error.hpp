#ifndef ASN1C_ERROR_HPP_ZQ3ULNWP
#define ASN1C_ERROR_HPP_ZQ3ULNWP

#include <stdexcept>

struct asn_TYPE_descriptor_s;

namespace vanetza
{
namespace asn1
{

enum class ErrorCode
{
    Ok = 0,
    EncodeFailed,
    DecodeIncomplete,
    DecodeFailed,
    OutOfMemory
};

/**
 * Error value describing the outcome of an asn1c operation
 */
class asn1c_error
{
public:
    asn1c_error() = default;
    asn1c_error(ErrorCode code, const asn_TYPE_descriptor_s* root_type = nullptr,
        const asn_TYPE_descriptor_s* failed_type = nullptr) noexcept;

    explicit operator bool() const noexcept { return m_code != ErrorCode::Ok; }
    ErrorCode code() const noexcept { return m_code; }
    const asn_TYPE_descriptor_s* root_type() const noexcept { return m_root_type; }
    const asn_TYPE_descriptor_s* failed_type() const noexcept { return m_failed_type; }
    const char* root_type_name() const noexcept;
    const char* failed_type_name() const noexcept;

private:
    ErrorCode m_code = ErrorCode::Ok;
    const asn_TYPE_descriptor_s* m_root_type = nullptr;
    const asn_TYPE_descriptor_s* m_failed_type = nullptr;
};

/**
 * Exception carrying an asn1c_error
 */
class asn1c_exception : public std::runtime_error
{
public:
    explicit asn1c_exception(const asn1c_error& err);

    const asn1c_error& error() const noexcept { return m_error; }
    ErrorCode code() const noexcept { return m_error.code(); }
    const char* failed_type_name() const noexcept { return m_error.failed_type_name(); }

private:
    asn1c_error m_error;
};

} // namespace asn1
} // namespace vanetza

#endif /* ASN1C_ERROR_HPP_ZQ3ULNWP */
