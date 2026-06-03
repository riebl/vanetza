#pragma once

#include "main.hpp"
#include <CLI/App.hpp>
#include <memory>

namespace vanetza
{
namespace pki
{

std::shared_ptr<CLI::App> build_dc_command(const MainConfig&);

} // namespace pki
} // namespace vanetza