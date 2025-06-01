#include "MainWindow.h"
#include <ui_MainWindow.h>

#define NOMINMAX
#include <dwmapi.h>

namespace GUI {
    void MainWindow::decorate_dialog(QWidget *widget) {
        BOOL value = TRUE;
        DwmSetWindowAttribute(reinterpret_cast<HWND>(widget->winId()), DWMWA_USE_IMMERSIVE_DARK_MODE, &value, sizeof(value));
    }
}