#pragma once

#include <CLI/CLI.hpp>
#include <memory>

namespace vanetza
{
namespace pki
{

std::shared_ptr<CLI::App> build_key_command();

} // namespace pki
} // namespace vanetza
