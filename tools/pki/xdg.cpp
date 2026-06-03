#include "xdg.hpp"
#include <cstdlib>
#include <pwd.h>
#include <stdexcept>
#include <unistd.h>

namespace vanetza
{
namespace pki
{

namespace
{

std::filesystem::path lookup_xdg_env(const char* env)
{
    const char* env_value = std::getenv(env);
    if (env_value) {
        return std::filesystem::path(env_value);
    } else {
        return std::filesystem::path {};
    }
}

std::filesystem::path lookup_home()
{
    const char* home_value = std::getenv("HOME");
    if (home_value && home_value[0] != '\0') {
        return std::filesystem::path { home_value };
    }

    const passwd* pw = ::getpwuid(getuid());
    if (pw && pw->pw_dir) {
        return std::filesystem::path { pw->pw_dir };
    }

    throw std::runtime_error("cannot determine home directory");
}

} // namespace

std::filesystem::path xdg_config_home()
{
    auto config_home = lookup_xdg_env("XDG_CONFIG_HOME");
    if (config_home.empty()) {
        config_home = lookup_home() / ".config";
    }
    return config_home;
}

std::filesystem::path xdg_data_home()
{
    auto data_home = lookup_xdg_env("XDG_DATA_HOME");
    if (data_home.empty()) {
        data_home = lookup_home() / ".local/share";
    }
    return data_home;
}

} // namespace pki
} // namespace vanetza
