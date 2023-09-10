#include <vector>

#include "gtest/gtest.h"
#include "Base/Encoding.h"

static void encode_base64_url_no_padding_test(
        std::string_view data,
        std::string_view expected) {

    const auto actual = Base::Encoding::encode_base64_url_no_padding({
        reinterpret_cast<const uint8_t *>(data.data()),
        data.size()});

    EXPECT_EQ(actual, expected);
}

TEST(Encoding, encode_base64_url_no_padding__multiple) {
    encode_base64_url_no_padding_test("", "");
    encode_base64_url_no_padding_test("f", "Zg");
    encode_base64_url_no_padding_test("fo", "Zm8");
    encode_base64_url_no_padding_test("foo", "Zm9v");
    encode_base64_url_no_padding_test("foob", "Zm9vYg");
    encode_base64_url_no_padding_test("fooba", "Zm9vYmE");
    encode_base64_url_no_padding_test("foobar", "Zm9vYmFy");
    encode_base64_url_no_padding_test("Man", "TWFu");
    encode_base64_url_no_padding_test("Ma", "TWE");
    encode_base64_url_no_padding_test("M", "TQ");
}

static void decode_base64_url_no_padding_test(
        std::string_view data,
        std::string_view expected) {

    const auto result = Base::Encoding::decode_base64_any(data);
    const auto actual = std::string_view(reinterpret_cast<const char *>(result.data()), result.size());

    EXPECT_EQ(actual, expected);
}

TEST(Encoding, decode_base64_url_no_padding__multiple) {
    decode_base64_url_no_padding_test("", "");
    decode_base64_url_no_padding_test("Zg", "f");
    decode_base64_url_no_padding_test("Zm8", "fo");
    decode_base64_url_no_padding_test("Zm9v", "foo");
    decode_base64_url_no_padding_test("Zm9vYg", "foob");
    decode_base64_url_no_padding_test("Zm9vYmE", "fooba");
    decode_base64_url_no_padding_test("Zm9vYmFy", "foobar");
    decode_base64_url_no_padding_test("TWFu", "Man");
    decode_base64_url_no_padding_test("TWE", "Ma");
    decode_base64_url_no_padding_test("TQ", "M");
}

TEST(Encoding, decode_base64__multiple) {
    decode_base64_url_no_padding_test("", "");
    decode_base64_url_no_padding_test("Zg==", "f");
    decode_base64_url_no_padding_test("Zm8=", "fo");
    decode_base64_url_no_padding_test("Zm9v", "foo");
    decode_base64_url_no_padding_test("Zm9vYg==", "foob");
    decode_base64_url_no_padding_test("Zm9vYmE=", "fooba");
    decode_base64_url_no_padding_test("Zm9vYmFy", "foobar");
    decode_base64_url_no_padding_test("TWFu", "Man");
    decode_base64_url_no_padding_test("TWE=", "Ma");
    decode_base64_url_no_padding_test("TQ==", "M");
}

TEST(Encoding, decode_base64_url_no_padding__full_alphabet) {

    const auto s = Base::ZString(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_");

    const auto result = Base::Encoding::decode_base64_any(s);

    Base::ZBytes expected {
            0x00,0x10,0x83,0x10,0x51,0x87,0x20,0x92,
            0x8b,0x30,0xd3,0x8f,0x41,0x14,0x93,0x51,
            0x55,0x97,0x61,0x96,0x9b,0x71,0xd7,0x9f,
            0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,
            0xab,0xb2,0xdb,0xaf,0xc3,0x1c,0xb3,0xd3,
            0x5d,0xb7,0xe3,0x9e,0xbb,0xf3,0xdf,0xbf,
    };

    EXPECT_EQ(result, expected);
}

TEST(Encoding, decode_base64__full_alphabet) {

    const auto s = Base::ZString(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/");

    const auto result = Base::Encoding::decode_base64_any(s);

    Base::ZBytes expected {
            0x00,0x10,0x83,0x10,0x51,0x87,0x20,0x92,
            0x8b,0x30,0xd3,0x8f,0x41,0x14,0x93,0x51,
            0x55,0x97,0x61,0x96,0x9b,0x71,0xd7,0x9f,
            0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,
            0xab,0xb2,0xdb,0xaf,0xc3,0x1c,0xb3,0xd3,
            0x5d,0xb7,0xe3,0x9e,0xbb,0xf3,0xdf,0xbf,
    };

    EXPECT_EQ(result, expected);
}

TEST(Encoding, encode_base64_url_no_padding__full_alphabet) {

    Base::ZBytes v {
        0x00,0x10,0x83,0x10,0x51,0x87,0x20,0x92,
        0x8b,0x30,0xd3,0x8f,0x41,0x14,0x93,0x51,
        0x55,0x97,0x61,0x96,0x9b,0x71,0xd7,0x9f,
        0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,
        0xab,0xb2,0xdb,0xaf,0xc3,0x1c,0xb3,0xd3,
        0x5d,0xb7,0xe3,0x9e,0xbb,0xf3,0xdf,0xbf,
    };

    const auto result = Base::Encoding::encode_base64_url_no_padding(v);

    const auto expected = Base::ZString(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_");

    EXPECT_EQ(result, expected);
}

TEST(Encoding, encode_base16) {

    Base::ZBytes v {
            0x00,0x10,0x83,0x10,0x51,0x87,0x20,0x92,
            0x8b,0x30,0xd3,0x8f,0x41,0x14,0x93,0x51,
            0x55,0x97,0x61,0x96,0x9b,0x71,0xd7,0x9f,
            0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,
            0xab,0xb2,0xdb,0xaf,0xc3,0x1c,0xb3,0xd3,
            0x5d,0xb7,0xe3,0x9e,0xbb,0xf3,0xdf,0xbf,
    };

    const auto result = Base::Encoding::encode_hex_lower(v);

    const auto expected = Base::ZString(
            "0010831051872092"
            "8b30d38f41149351"
            "559761969b71d79f"
            "8218a39259a7a29a"
            "abb2dbafc31cb3d3"
            "5db7e39ebbf3dfbf");

    EXPECT_EQ(result, expected);
}

TEST(Encoding, decode_base16) {

    const auto s = Base::ZString(
            "0010831051872092"
            "8b30d38f41149351"
            "559761969b71d79f"
            "8218a39259a7a29a"
            "abb2dbafc31cb3d3"
            "5db7e39ebbf3dfbf");

    Base::ZBytes expected {
            0x00,0x10,0x83,0x10,0x51,0x87,0x20,0x92,
            0x8b,0x30,0xd3,0x8f,0x41,0x14,0x93,0x51,
            0x55,0x97,0x61,0x96,0x9b,0x71,0xd7,0x9f,
            0x82,0x18,0xa3,0x92,0x59,0xa7,0xa2,0x9a,
            0xab,0xb2,0xdb,0xaf,0xc3,0x1c,0xb3,0xd3,
            0x5d,0xb7,0xe3,0x9e,0xbb,0xf3,0xdf,0xbf,
    };

    const auto result = Base::Encoding::decode_hex_any(s);

    EXPECT_EQ(result, expected);
}