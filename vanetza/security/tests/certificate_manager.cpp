#include <vanetza/security/certificate_manager.hpp>
#include <gtest/gtest.h>

using namespace vanetza;

class CertificateManager : public ::testing::Test
{
public:
    CertificateManager() : time_now(0), cert_manager(time_now)
    {
    }

protected:
    geonet::Timestamp time_now;
    security::CertificateManager cert_manager;
};

TEST_F(CertificateManager, sign_shb)
{
    security::EncapRequest request;

    security::EncapConfirm confirm = cert_manager.sign_message(request);
}
