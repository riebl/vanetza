#ifndef PKI_TESTS_UNIQUE_TEST_DIRECTORY_HPP
#define PKI_TESTS_UNIQUE_TEST_DIRECTORY_HPP

#include <filesystem>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

#ifndef WORK_DIR
#error "WORK_DIR has to name a private, writable directory for test scratch files"
#endif

namespace vanetza
{
namespace pki
{

/**
 * Create a fresh directory with a unique name for exclusive use by one test case.
 *
 * \param prefix leading part of the directory name
 * \return path of the created directory
 */
inline std::filesystem::path create_unique_test_directory(const std::string& prefix)
{
    const std::filesystem::path base { WORK_DIR };
    std::random_device random;

    for (int attempt = 0; attempt < 16; ++attempt) {
        std::ostringstream name;
        name << prefix << '.' << std::hex << random();
        const std::filesystem::path directory = base / name.str();
        if (std::filesystem::create_directory(directory)) {
            return directory;
        }
    }

    throw std::runtime_error("failed to create unique test directory below " + base.string());
}

} // namespace pki
} // namespace vanetza

#endif /* PKI_TESTS_UNIQUE_TEST_DIRECTORY_HPP */
