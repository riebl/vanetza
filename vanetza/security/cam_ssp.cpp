#include <vanetza/security/cam_ssp.hpp>

namespace vanetza
{
namespace security
{

CamPermissions::CamPermissions() : m_bits(0)
{
}

CamPermissions::CamPermissions(CamPermission cp) : m_bits(static_cast<value_type>(cp))
{
}

CamPermissions::CamPermissions(const std::initializer_list<CamPermission>& cps) : m_bits(0)
{
    for (CamPermission cp : cps) {
        add(cp);
    }
}

bool CamPermissions::has(CamPermission cp) const
{
    const auto cp_raw = static_cast<value_type>(cp);
    return (m_bits & cp_raw) == cp_raw;
}

bool CamPermissions::has(const std::initializer_list<CamPermission>& cps) const
{
    for (CamPermission cp : cps) {
        if (!has(cp)) return false;
    }
    return true;
}

bool CamPermissions::none() const
{
    return m_bits == 0;
}

CamPermissions& CamPermissions::add(CamPermission cp)
{
    m_bits |= static_cast<value_type>(cp);
    return *this;
}

CamPermissions& CamPermissions::remove(CamPermission cp)
{
    m_bits &= ~static_cast<value_type>(cp);
    return *this;
}

ByteBuffer CamPermissions::encode() const
{
    return ByteBuffer({1, static_cast<uint8_t>(m_bits), static_cast<uint8_t>(m_bits >> 8) });
}

CamPermissions CamPermissions::decode(const ByteBuffer& buffer)
{
    CamPermissions permissions;
    if (buffer.size() == 3 && buffer[0] == 1) {
        permissions.m_bits = buffer[2];
        permissions.m_bits <<= 8;
        permissions.m_bits |= buffer[1];
    }
    return permissions;
}

} // namespace security
} // namespace vanetza
