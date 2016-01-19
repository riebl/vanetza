#include <gtest/gtest.h>
#include <vanetza/common/runtime.hpp>
#include <chrono>
#include <functional>
#include <string>

using namespace vanetza;
using std::chrono::hours;
using std::chrono::minutes;

TEST(Runtime, default_construction)
{
    Runtime r;
    EXPECT_EQ(Clock::time_point::min(), r.now());
}

TEST(Runtime, time_progress_absolute)
{
    Runtime r;

    const Clock::time_point t1 { hours(27) };
    r.trigger(t1);
    EXPECT_EQ(t1, r.now());

    const Clock::time_point t2 { hours(28) };
    r.trigger(t2);
    EXPECT_EQ(t2, r.now());
}

TEST(Runtime, time_progress_relative)
{
    Runtime r;

    r.trigger(hours(3));
    EXPECT_EQ(Clock::time_point { hours(3) }, r.now());

    r.trigger(hours(2));
    EXPECT_EQ(Clock::time_point { hours(5) }, r.now());
}

TEST(Runtime, sorting)
{
    Runtime r;
    r.trigger(hours(3));
    EXPECT_EQ(Clock::time_point::max(), r.next());

    auto cb = [](Clock::time_point) {};
    const auto tp1 = Clock::time_point { hours(2) };
    r.schedule(tp1, cb);
    EXPECT_EQ(tp1, r.next());

    r.schedule(Clock::time_point { hours(3) }, cb);
    EXPECT_EQ(tp1, r.next());

    const auto tp2 = Clock::time_point { hours(1) };
    r.schedule(tp2, cb);
    EXPECT_EQ(tp2, r.next());

    r.schedule(minutes(30), cb);
    EXPECT_EQ(tp2, r.next());
}

TEST(Runtime, scheduling)
{
    Runtime r;
    r.trigger(hours(5));

    using tp = Clock::time_point;
    using namespace std::placeholders;
    std::string seq;
    auto cb = [&seq, &r](const char* str, tp called) {
        SCOPED_TRACE(testing::Message() << "callback for " << str);
        EXPECT_EQ(r.now(), called);
        seq.append(str);
    };

    r.schedule(hours(10), std::bind<void>(cb, "1", _1));
    r.schedule(hours(11), std::bind<void>(cb, "2", _1));
    r.schedule(hours(11), std::bind<void>(cb, "2", _1));
    r.schedule(hours(5), std::bind<void>(cb, "3", _1));

    r.trigger(hours(4));
    EXPECT_EQ("", seq);

    r.trigger(hours(1));
    EXPECT_EQ("3", seq);

    r.trigger(hours(5));
    EXPECT_EQ("31", seq);

    // schedule expired callback (immediate invocation at next trigger)
    r.schedule(tp { hours(2) }, std::bind<void>(cb, "4", _1));
    r.trigger(hours(0));
    EXPECT_EQ("314", seq);

    r.trigger(hours(5));
    EXPECT_EQ("31422", seq);

    r.trigger(tp::max());
    EXPECT_EQ("31422", seq);
}
