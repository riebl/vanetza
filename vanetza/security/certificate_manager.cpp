#include <vanetza/common/runtime.hpp>
#include <vanetza/security/certificate_manager.hpp>
#include <vanetza/security/naive_certificate_manager.hpp>
#include <vanetza/security/null_certificate_manager.hpp>

namespace vanetza
{
namespace security
{
namespace
{

Factory<CertificateManager, Runtime&> setup_factory()
{
    Factory<CertificateManager, Runtime&> factory;
    factory.add("Naive", [](Runtime& rt) {
            return std::unique_ptr<CertificateManager> { new NaiveCertificateManager(rt.now()) };
    });
    factory.add("Null", [](Runtime&) {
            return std::unique_ptr<CertificateManager> { new NullCertificateManager() };
    });
    return factory;
}

} // namespace

const Factory<CertificateManager, Runtime&>& builtin_certificate_managers()
{
    static const auto factory = setup_factory();
    return factory;
};

} // namespace security
} // namespace vanetza
