#include "xdg.hpp"
#include <array>
#include <cstdlib>
#include <optional>
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

std::optional<std::filesystem::path> lookup_passwd_home()
{
    // getpwuid_r stores the strings of the passwd entry in a caller-provided buffer
    std::array<char, 4096> buffer;
    passwd pw;
    passwd* found = nullptr; // set to &pw if an entry exists, otherwise nullptr
    if (::getpwuid_r(::getuid(), &pw, buffer.data(), buffer.size(), &found) == 0 && found != nullptr) {
        if (pw.pw_dir != nullptr && pw.pw_dir[0] != '\0') {
            return std::filesystem::path { pw.pw_dir };
        }
    }
    return std::nullopt;
}

std::filesystem::path lookup_home()
{
    const char* home_value = std::getenv("HOME");
    if (home_value && home_value[0] != '\0') {
        return std::filesystem::path { home_value };
    }

    if (auto home = lookup_passwd_home()) {
        return *home;
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
