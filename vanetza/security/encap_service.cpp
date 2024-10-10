#include <vanetza/security/encap_service.hpp>

namespace vanetza
{
namespace security
{

EncapConfirm EncapConfirm::from(SignConfirm&& sign_confirm)
{
    if (sign_confirm.secured_message) {
        return EncapConfirm { std::move(*sign_confirm.secured_message) };
    } else {
        return EncapConfirm { sign_confirm.error };
    }
}

const SecuredMessage* EncapConfirm::secured_message() const
{
    return boost::get<SecuredMessage>(this);
}

SecuredMessage* EncapConfirm::secured_message()
{
    return boost::get<SecuredMessage>(this);
}

EncapConfirm dispatch(EncapRequest&& encap_request, SignService* sign_service)
{
    struct Dispatcher : boost::static_visitor<EncapConfirm>
    {
        Dispatcher(SignService* sign_service) : m_sign_service(sign_service) {}

        EncapConfirm operator()(SignRequest& request)
        {
            if (m_sign_service) {
                return EncapConfirm::from(m_sign_service->sign(std::move(request)));
            } else {
                return EncapConfirm::from(SignConfirm::failure(SignConfirmError::No_Service));
            }
        }

        SignService* m_sign_service;
    };

    Dispatcher dispatcher(sign_service);
    return boost::apply_visitor(dispatcher, encap_request);
}

} // namespace security
} // namespace vanetza
