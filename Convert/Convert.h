#pragma once

#include <string_view>
#include <span>

#include <QString>
#include <QByteArray>

namespace Convert {

    std::u8string to_u8string(const QString &s);
    std::span<const uint8_t> to_const_span(const QByteArray &a);
    QString to_qt_string(const std::u8string_view &s);
    QString to_qt_string_from_utf8(const std::span<const uint8_t> &s);
    QByteArray to_qt_byte_array(const std::span<const uint8_t> &s);



}