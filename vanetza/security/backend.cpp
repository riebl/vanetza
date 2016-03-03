#include <vanetza/security/backend.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/backend_null.hpp>
#include <cassert>
#include <functional>
#include <map>

namespace vanetza
{
namespace security
{

template<typename T>
std::unique_ptr<T> make_unique(T* t)
{
    return std::unique_ptr<T>(t);
}

class BackendFactory
{
public:
    using BackendGeneratorFn = std::function<std::unique_ptr<Backend>()>;

    BackendFactory()
    {
        // first inserted backend is implicitly "default"
        attach("CryptoPP", []() { return make_unique(new BackendCryptoPP()); });
        attach("Null", []() { return make_unique(new BackendNull()); });
    }

    std::unique_ptr<Backend> create(const std::string& name)
    {
        assert(!backends.empty());
        std::unique_ptr<Backend> backend;

        if (name == "default") {
            assert(default_backend);
            backend = default_backend();
        } else {
            auto found = backends.find(name);
            if (found != backends.end()) {
                backend = (found->second)();
            }
        }

        return backend;
    }

private:
    void attach(const std::string& name, BackendGeneratorFn gen)
    {
        backends[name] = gen;
        if (!default_backend) {
            default_backend = gen;
        }
    }

    std::map<std::string, BackendGeneratorFn> backends;
    BackendGeneratorFn default_backend;
};

std::unique_ptr<Backend> create_backend(const std::string& name)
{
    static BackendFactory factory;
    return factory.create(name);
}

} // namespace security
} // namespace vanetza
