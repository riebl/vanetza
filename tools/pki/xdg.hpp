#pragma once
#include <filesystem>

namespace vanetza
{
namespace pki
{

std::filesystem::path xdg_config_home();
std::filesystem::path xdg_data_home();

} // namespace pki
} // namespace vanetza
