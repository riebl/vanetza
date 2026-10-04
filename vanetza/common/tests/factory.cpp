#include <gtest/gtest.h>
#include <vanetza/common/factory.hpp>

TEST(Factory, copy_without_default)
{
    vanetza::Factory<int> original;
    auto copy = original;
    EXPECT_EQ(nullptr, copy.create());
}

TEST(Factory, copied_default_survives_source_replacement)
{
    vanetza::Factory<int> copy;
    {
        vanetza::Factory<int> original;
        original.add("value", [] { return std::unique_ptr<int>(new int(7)); });
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
        return std::unique_ptr<int>(new int(++value));
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
    EXPECT_EQ(4, *factory.create(std::unique_ptr<int>(new int(4))));
    EXPECT_EQ(5, *factory.create("value", std::unique_ptr<int>(new int(5))));
}
