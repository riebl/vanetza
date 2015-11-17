#include <vanetza/security/certificate_manager.hpp>
#include <gtest/gtest.h>

using namespace vanetza;

class CertificateManager : public ::testing::Test
{
protected:
    security::CertificateManager cert_manager;
};

TEST_F(CertificateManager, sign_shb)
{
    security::EncapRequest request;

    security::EncapConfirm confirm = cert_manager.sign_message(request);
}
