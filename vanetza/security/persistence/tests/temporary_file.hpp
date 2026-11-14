#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace vanetza
{
namespace security
{
namespace persistence
{

// path of a file in the temporary directory, removed after the test
class TemporaryFileTest : public ::testing::Test
{
protected:
    void TearDown() override
    {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    void write(const ByteBuffer& content)
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(content.data()), content.size());
    }

    void write(const std::string& content)
    {
        write(ByteBuffer(content.begin(), content.end()));
    }

    ByteBuffer read() const
    {
        std::ifstream file(path, std::ios::binary);
        return ByteBuffer(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    }

    // file in gtest's temporary directory named after the current test
    static std::filesystem::path temporary_path()
    {
        const ::testing::TestInfo* test = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string name = std::string(test->test_suite_name()) + "." + test->name();
        return std::filesystem::path(::testing::TempDir()) / name;
    }

    const std::filesystem::path path = temporary_path();
    const std::filesystem::path missing_path = std::filesystem::path(::testing::TempDir()) / "missing" / "file";
};

} // namespace persistence
} // namespace security
} // namespace vanetza
