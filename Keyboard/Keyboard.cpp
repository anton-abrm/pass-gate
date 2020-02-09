#include "Keyboard.h"

#include <memory>

extern "C" {
#include <xdo.h>
}

namespace Keyboard {

    void enter_text(const std::u8string_view &text) {

        std::unique_ptr<xdo_t, decltype(&xdo_free)> xdo(
                xdo_new(nullptr), &xdo_free);

        Window active_window{0};

        xdo_select_window_with_click(xdo.get(), &active_window);
        xdo_click_window(xdo.get(), active_window, 1);

        usleep(100000);

        xdo_enter_text_window(
                xdo.get(),
                active_window,
                reinterpret_cast<const char *>(text.data()),
                100000);
    }
}