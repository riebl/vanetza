#pragma once
#include <vanetza/common/its_aid.hpp>

namespace vanetza
{

// forward declarations
class PositionProvider;
class Runtime;

namespace security
{
namespace v3
{

// forward declarations
class CertificateView;

class CertificateValidator
{
public:
    enum class Verdict
    {
        Unknown,
        Valid,
        Expired,
        Revoked,
        OutsideRegion,
        InsufficientPermission,
        Misconfiguration,
    };

    /**
     * Check if a certificate can be used for signing a message
     * \param certificate pre-validated AT certificate
     * \param app ITS-AID of the message to be signed
     */
    virtual Verdict valid_for_signing(const CertificateView& certificate, ItsAid app) = 0;

    virtual ~CertificateValidator() = default;
};

class DefaultCertificateValidator : public CertificateValidator
{
public:
    Verdict valid_for_signing(const CertificateView&, ItsAid) override;
    
    void use_runtime(const Runtime* runtime);
    void use_position_provider(PositionProvider* provider);

    void disable_time_checks(bool flag);
    void disable_location_checks(bool flag);

private:
    const Runtime* m_runtime = nullptr;
    PositionProvider* m_position_provider = nullptr;
    bool m_disable_time_checks = false;
    bool m_disable_location_checks = false;
};

class NullCertificateValidator : public CertificateValidator
{
public:
    Verdict valid_for_signing(const CertificateView&, ItsAid) override
    {
        return Verdict::Valid;
    }
};

} // namespace v3
} // namespace security
} // namespace vanetza
