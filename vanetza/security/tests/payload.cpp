#include <gtest/gtest.h>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/tests/check_payload.hpp>
#include <vanetza/security/tests/serialization.hpp>

using namespace vanetza::security;

TEST(Payload, Serialize)
{
    Payload p;
    p.type = PayloadType::Unsecured;
    p.buffer = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    check(p, serialize_roundtrip(p));
}

