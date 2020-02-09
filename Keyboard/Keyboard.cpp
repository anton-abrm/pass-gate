#include "Keyboard.h"
#include "Base/ZString.h"

#ifdef __linux__

#include <memory>

extern "C" {
#include <xdo.h>
}

#endif

namespace Keyboard {

    void enter_text(std::string_view text) {

#ifdef __linux__

        std::unique_ptr<xdo_t, decltype(&xdo_free)> xdo(
                xdo_new(nullptr), &xdo_free);

        Window active_window{0};

        xdo_select_window_with_click(xdo.get(), &active_window);
        xdo_click_window(xdo.get(), active_window, 1);

        usleep(100000);

        xdo_enter_text_window(
                xdo.get(),
                active_window,
                Base::ZString(text).c_str(),
                100000);
#endif

    }
}