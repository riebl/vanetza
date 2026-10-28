#include <gtest/gtest.h>
#include <vanetza/common/expected.hpp>
#include <memory>
#include <string>
#include <system_error>
#include <type_traits>

using namespace vanetza;

namespace
{

using Error = std::error_code;

Error some_error()
{
    return std::make_error_code(std::errc::invalid_argument);
}

// counts living instances to reveal missing or duplicate destruction
struct Tracked
{
    static int instances;

    Tracked() { ++instances; }
    Tracked(const Tracked&) { ++instances; }
    Tracked(Tracked&&) noexcept { ++instances; }
    Tracked& operator=(const Tracked&) = default;
    Tracked& operator=(Tracked&&) noexcept = default;
    ~Tracked() { --instances; }
};

int Tracked::instances = 0;

} // namespace

TEST(Expected, value)
{
    expected<int, Error> result = 42;
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(result.has_error());
    EXPECT_TRUE(result);
    EXPECT_EQ(42, *result);
    EXPECT_EQ(42, result.value());
}

TEST(Expected, error)
{
    expected<int, Error> result = unexpected<Error>(some_error());
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(result.has_error());
    EXPECT_FALSE(result);
    EXPECT_EQ(some_error(), result.error());
}

TEST(Expected, error_without_unexpected)
{
    expected<int> result = some_error();
    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(some_error(), result.error());
}

// error type defaults to std::error_code
static_assert(std::is_same<expected<int>::error_type, std::error_code>::value, "default error type");

// an argument convertible to value and error type is ambiguous and needs unexpected
static_assert(!std::is_convertible<int, expected<long, int>>::value, "ambiguous argument");

TEST(Expected, default_constructed_holds_value)
{
    expected<int, Error> result;
    ASSERT_TRUE(result);
    EXPECT_EQ(0, *result);
}

TEST(Expected, value_or)
{
    expected<int, Error> value = 42;
    expected<int, Error> error = unexpected<Error>(some_error());
    EXPECT_EQ(42, value.value_or(7));
    EXPECT_EQ(7, error.value_or(7));
}

TEST(Expected, value_throws_system_error_for_error_code)
{
    expected<int> result = some_error();
    try {
        result.value();
        FAIL() << "value() returned despite error";
    } catch (const std::system_error& e) {
        EXPECT_EQ(some_error(), e.code());
    }
}

TEST(Expected, value_throws_bad_expected_access_for_other_errors)
{
    expected<int, std::string> result = unexpected<std::string>("failure");
    try {
        result.value();
        FAIL() << "value() returned despite error";
    } catch (const bad_expected_access<std::string>& e) {
        EXPECT_EQ("failure", e.error());
    }
}

TEST(Expected, member_access)
{
    expected<std::string, Error> result = std::string("abc");
    EXPECT_EQ(3u, result->size());
}

TEST(Expected, copy)
{
    expected<std::string, Error> value = std::string("abc");
    expected<std::string, Error> error = unexpected<Error>(some_error());

    expected<std::string, Error> value_copy = value;
    expected<std::string, Error> error_copy = error;
    ASSERT_TRUE(value_copy);
    EXPECT_EQ("abc", *value_copy);
    ASSERT_FALSE(error_copy);
    EXPECT_EQ(some_error(), error_copy.error());
}

TEST(Expected, move_only_value)
{
    expected<std::unique_ptr<int>, Error> source = std::unique_ptr<int>(new int(42));
    expected<std::unique_ptr<int>, Error> target = std::move(source);
    ASSERT_TRUE(target);
    std::unique_ptr<int> extracted = *std::move(target);
    ASSERT_TRUE(extracted);
    EXPECT_EQ(42, *extracted);
}

TEST(Expected, destruction_releases_value)
{
    {
        expected<Tracked, Error> result = Tracked();
        EXPECT_EQ(1, Tracked::instances);
    }
    EXPECT_EQ(0, Tracked::instances);
}

TEST(Expected, error_assignment_releases_value)
{
    expected<Tracked, Error> result = Tracked();
    result = unexpected<Error>(some_error());
    EXPECT_FALSE(result);
    EXPECT_EQ(some_error(), result.error());
    EXPECT_EQ(0, Tracked::instances);
}

TEST(Expected, value_assignment_replaces_error)
{
    expected<Tracked, Error> result = unexpected<Error>(some_error());
    result = Tracked();
    EXPECT_TRUE(result);
    EXPECT_EQ(1, Tracked::instances);
}

TEST(Expected, copy_assignment_takes_over_state)
{
    expected<Tracked, Error> result = Tracked();
    const expected<Tracked, Error> error = unexpected<Error>(some_error());
    result = error;
    ASSERT_FALSE(result);
    EXPECT_EQ(some_error(), result.error());
    EXPECT_EQ(0, Tracked::instances);

    const expected<Tracked, Error> value = Tracked();
    result = value;
    EXPECT_TRUE(result);
    EXPECT_EQ(2, Tracked::instances);
}

#ifndef NDEBUG
TEST(Expected, value_access_on_error_asserts)
{
    expected<std::string> result = some_error();
    EXPECT_DEATH(*result, "");
    EXPECT_DEATH(static_cast<void>(result->size()), "");
}

TEST(Expected, error_access_on_value_asserts)
{
    expected<std::string> result = std::string("abc");
    EXPECT_DEATH(result.error(), "");
}
#endif

// std::expected<bool, E> would store has_value() when constructed from a bool-convertible expected
static_assert(!std::is_constructible<bool, expected<bool, Error>>::value, "bool result must not convert to bool");

#if defined(__cpp_lib_expected)
TEST(Expected, converts_to_std_expected)
{
    std::expected<int, Error> value = expected<int, Error>(42);
    std::expected<int, Error> error = expected<int, Error>(unexpected<Error>(some_error()));
    ASSERT_TRUE(value);
    EXPECT_EQ(42, *value);
    ASSERT_FALSE(error);
    EXPECT_EQ(some_error(), error.error());
}

TEST(Expected, converts_move_only_value_to_std_expected)
{
    std::expected<std::unique_ptr<int>, Error> converted =
        expected<std::unique_ptr<int>, Error>(std::unique_ptr<int>(new int(42)));
    ASSERT_TRUE(converted);
    EXPECT_EQ(42, **converted);
}

TEST(Expected, bool_value_converts_to_std_expected)
{
    const expected<bool, Error> result = false;
    std::expected<bool, Error> converted(result);
    ASSERT_TRUE(converted.has_value());
    EXPECT_FALSE(*converted);
}

#endif
