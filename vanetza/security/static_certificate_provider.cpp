#include <vanetza/security/static_certificate_provider.hpp>

namespace vanetza
{
namespace security
{

StaticCertificateProvider::StaticCertificateProvider(const CertificateVariant& authorization_ticket,
        const ecdsa256::PrivateKey& authorization_ticket_key) :
    StaticCertificateProvider(authorization_ticket, authorization_ticket_key, std::list<CertificateVariant> {})
{
}

StaticCertificateProvider::StaticCertificateProvider(const CertificateVariant& authorization_ticket,
        const ecdsa256::PrivateKey& authorization_ticket_key, const std::list<CertificateVariant>& chain) :
    authorization_ticket(authorization_ticket), authorization_ticket_key(authorization_ticket_key), chain(chain)
{
    class version_checker : public boost::static_visitor<int>
    {
    public:
        int operator()(const Certificate& cert) const
        {
            return 2;
        }
        
        int operator()(const CertificateV3& cert) const
        {
            return 3;
        }
    };
    version_ = boost::apply_visitor(version_checker(), authorization_ticket);
    class version_visitor : public boost::static_visitor<bool>
    {
    public:
        version_visitor(int version) : version_(version){}
        bool operator()(const Certificate& cert) const
        {
            return (version_==2);
        }
        
        bool operator()(const CertificateV3& cert) const
        {
            return (version_==3);
        }
        int version_;
    };
    bool incongruent_version = false;
    version_visitor visitor(version_);
    for (const auto& cert: chain){
        if (!boost::apply_visitor(visitor, cert)){
            incongruent_version = true;
        }
    }
    if (!boost::apply_visitor(visitor, authorization_ticket)){
        incongruent_version = true;
    }
    if(incongruent_version){
        throw std::runtime_error("The versions of the certificates must be all the same");
    }
}

int StaticCertificateProvider::version()
{
    return version_;
}

const ecdsa256::PrivateKey& StaticCertificateProvider::own_private_key()
{
    return authorization_ticket_key;
}

std::list<CertificateVariant> StaticCertificateProvider::own_chain()
{
    return chain;
}

const CertificateVariant& StaticCertificateProvider::own_certificate()
{
    return authorization_ticket;
}


} // namespace security
} // namespace vanetza
