#include <Convert/Convert.h>

namespace Convert {

    std::u8string to_u8string(const QString &s) {
        const auto utf8_bytes = s.toUtf8();
        return {reinterpret_cast<const char8_t *>(utf8_bytes.constData()),
                static_cast<std::u8string::size_type>(utf8_bytes.size())};
    }

    QString to_qt_string(const std::u8string_view &s) {
        return QString::fromUtf8(reinterpret_cast<const char *>(s.data()),
                                 static_cast<int>(s.size()));
    }

    QByteArray to_qt_byte_array(const std::span<const uint8_t> &s) {
        return {reinterpret_cast<const char *>(s.data()),
                static_cast<int>(s.size())};
    }

    std::span<const uint8_t> to_const_span(const QByteArray &a) {
        return {
            reinterpret_cast<const uint8_t *>(a.constData()),
            static_cast<std::span<const uint8_t>::size_type>(a.size())
        };
    }

    QString to_qt_string_from_utf8(const std::span<const uint8_t> &s) {
        return QString::fromUtf8(reinterpret_cast<const char *>(s.data()),
                                 static_cast<int>(s.size()));
    }
}
