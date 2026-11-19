#include <vector>

#include "gtest/gtest.h"
#include "Password/Password.h"

static void decode_hhhs_test(const Base::ZString &encoded, const Base::ZBytes& expected) {
    EXPECT_EQ(Password::decode_hhhs(encoded), expected);
}

static void encode_hhhs_test(const Base::ZBytes& bytes, const Base::ZString &expected) {
    EXPECT_EQ(Password::encode_hhhs(bytes), expected);
}

TEST(Password, decode_hhhh) {
    decode_hhhs_test("Pa$$wrd!", { 0x35, 0x8e, 0xba, 0xb2, 0x76, 0xf8 });
}

TEST(Password, encode_hhhh) {
    encode_hhhs_test( { 0x35, 0x8e, 0xba, 0xb2, 0x76, 0xf8 }, "Pa$$wrd!");
}

// 11 chars = 66 bits = 8 bytes + 2 spare bits in the last character.
// 'A' (index 0) has zero spare bits, so "ABCDEFGHJKA" is the canonical encoding.
TEST(Password, decode_hhhs_ABCDEFGHJKA) {
    decode_hhhs_test("ABCDEFGHJKA", { 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x90 });
}

TEST(Password, encode_hhhs_ABCDEFGHJKA) {
    encode_hhhs_test({ 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x90 }, "ABCDEFGHJKA");
}

// 'B' (index 1) has non-zero spare bits, which do not fit into the 8 bytes.
// Decoding must reject it instead of silently dropping them.
TEST(Password, decode_hhhs_ABCDEFGHJKB) {
    EXPECT_EQ(Password::decode_hhhs("ABCDEFGHJKB"), std::nullopt);
}

TEST(Password, encode_hhhs_cannot_produce_ABCDEFGHJKB) {
    const Base::ZBytes bytes = { 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x90 };
    EXPECT_NE(Password::encode_hhhs(bytes), "ABCDEFGHJKB");
}


