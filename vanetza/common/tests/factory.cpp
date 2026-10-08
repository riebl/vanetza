#include <gtest/gtest.h>
#include <vanetza/common/factory.hpp>

TEST(Factory, copy_without_default)
{
    vanetza::Factory<int> original;
    vanetza::Factory<int> copy(original);
    EXPECT_EQ(nullptr, copy.create());
}

TEST(Factory, default_presence_is_independent_of_name)
{
    vanetza::Factory<int> factory;
    factory.add("", [] { return std::make_unique<int>(9); });
    ASSERT_TRUE(factory.configure_default(""));
    EXPECT_EQ(9, *factory.create());
    EXPECT_FALSE(factory.configure_default("missing"));
    EXPECT_EQ(nullptr, factory.create());
}

TEST(Factory, copied_default_survives_source_replacement)
{
    vanetza::Factory<int> copy;
    {
        vanetza::Factory<int> original;
        original.add("value", [] { return std::make_unique<int>(7); });
        ASSERT_TRUE(original.configure_default("value"));
        copy = original;
        original = vanetza::Factory<int>();
    }
    auto result = copy.create();
    ASSERT_NE(nullptr, result);
    EXPECT_EQ(7, *result);
}

TEST(Factory, reference_argument_keeps_reference)
{
    vanetza::Factory<int, int&> factory;
    factory.add("increment", [](int& value) {
        return std::make_unique<int>(++value);
    });
    ASSERT_TRUE(factory.configure_default("increment"));
    int value = 1;
    EXPECT_EQ(2, *factory.create(value));
    EXPECT_EQ(2, value);
    EXPECT_EQ(3, *factory.create("increment", value));
    EXPECT_EQ(3, value);
}

TEST(Factory, value_argument_supports_move_only_values)
{
    vanetza::Factory<int, std::unique_ptr<int>> factory;
    factory.add("value", [](std::unique_ptr<int> value) { return value; });
    ASSERT_TRUE(factory.configure_default("value"));
    EXPECT_EQ(4, *factory.create(std::make_unique<int>(4)));
    EXPECT_EQ(5, *factory.create("value", std::make_unique<int>(5)));
}

TEST(Factory, const_reference_argument_keeps_identity)
{
    vanetza::Factory<int, const int&> factory;
    const int value = 6;
    factory.add("value", [&value](const int& argument) {
        EXPECT_EQ(&value, &argument);
        return std::make_unique<int>(argument);
    });
    ASSERT_TRUE(factory.configure_default("value"));
    EXPECT_EQ(6, *factory.create(value));
    EXPECT_EQ(6, *factory.create("value", value));
}

TEST(Factory, rvalue_reference_argument_supports_move_only_values)
{
    vanetza::Factory<int, std::unique_ptr<int>&&> factory;
    factory.add("value", [](std::unique_ptr<int>&& value) { return std::move(value); });
    ASSERT_TRUE(factory.configure_default("value"));
    auto first = std::make_unique<int>(7);
    EXPECT_EQ(7, *factory.create(std::move(first)));
    EXPECT_EQ(nullptr, first);
    auto second = std::make_unique<int>(8);
    EXPECT_EQ(8, *factory.create("value", std::move(second)));
    EXPECT_EQ(nullptr, second);
}
