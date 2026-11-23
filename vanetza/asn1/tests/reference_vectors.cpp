#include "vector_codec.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifndef REFERENCE_VECTOR_DIR
#error "REFERENCE_VECTOR_DIR must be defined by the build"
#endif

namespace
{

struct VectorCase
{
    std::string name;
    std::string message;
};

const std::vector<VectorCase>& vector_cases()
{
    static const std::vector<VectorCase> cases = {
        {"mapem", "mapem"},
        {"spatem_cycle_00s", "spatem"},
        {"spatem_cycle_10s", "spatem"},
        {"spatem_cycle_20s", "spatem"},
        {"spatem_cycle_30s", "spatem"},
        {"spatem_cycle_40s", "spatem"},
        {"spatem_cycle_50s", "spatem"},
        {"spatem_cycle_60s", "spatem"},
        {"spatem_cycle_70s", "spatem"},
        {"spatem_hour_boundary", "spatem"},
        {"spatem_plan_change", "spatem"},
        {"srem_tram_request", "srem"},
        {"ssem_tram_processing", "ssem"},
    };
    return cases;
}

std::string vector_path(const std::string& name, const std::string& suffix)
{
    return std::string(REFERENCE_VECTOR_DIR) + "/" + name + suffix;
}

vanetza::ByteBuffer read_binary(const std::string& path)
{
    std::ifstream stream(path, std::ios::binary);
    EXPECT_TRUE(stream.good()) << "cannot open " << path;
    return vanetza::ByteBuffer(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

class ReferenceVectorTest : public ::testing::TestWithParam<VectorCase>
{
};

TEST_P(ReferenceVectorTest, XerToUperMatchesCommittedBytes)
{
    const VectorCase& c = GetParam();
    SCOPED_TRACE(c.name);

    const vanetza::ByteBuffer xer = read_binary(vector_path(c.name, ".xer"));
    const vanetza::ByteBuffer expected = read_binary(vector_path(c.name, ".uper"));

    const vanetza::ByteBuffer actual = reference_vectors::transcode(c.message, reference_vectors::Encoding::Xer, xer);
    EXPECT_EQ(actual, expected);
}

TEST_P(ReferenceVectorTest, UperToXerMatchesCommittedXer)
{
    const VectorCase& c = GetParam();
    SCOPED_TRACE(c.name);

    const vanetza::ByteBuffer uper = read_binary(vector_path(c.name, ".uper"));
    const vanetza::ByteBuffer expected = read_binary(vector_path(c.name, ".xer"));

    const vanetza::ByteBuffer actual = reference_vectors::transcode(c.message, reference_vectors::Encoding::Uper, uper);
    EXPECT_EQ(actual, expected);
}

INSTANTIATE_TEST_SUITE_P(ReferenceVectors, ReferenceVectorTest, ::testing::ValuesIn(vector_cases()),
    [](const ::testing::TestParamInfo<VectorCase>& vector_info) { return vector_info.param.name; });

TEST(ReferenceVectorNegative, UnknownMessageName)
{
    const vanetza::ByteBuffer empty;
    EXPECT_THROW(reference_vectors::transcode("unknown", reference_vectors::Encoding::Uper, empty), std::invalid_argument);
}

TEST(ReferenceVectorNegative, EmptyUper)
{
    const vanetza::ByteBuffer empty;
    EXPECT_THROW(reference_vectors::transcode("mapem", reference_vectors::Encoding::Uper, empty), std::runtime_error);
}

TEST(ReferenceVectorNegative, MalformedXer)
{
    const std::string text = "<not-a-valid-message/>";
    const vanetza::ByteBuffer malformed(text.begin(), text.end());
    EXPECT_THROW(reference_vectors::transcode("mapem", reference_vectors::Encoding::Xer, malformed), std::runtime_error);
}

} // namespace
