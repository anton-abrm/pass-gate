#include "MainWindow.h"
#include <ui_MainWindow.h>

#define NOMINMAX
#include <dwmapi.h>

namespace GUI {

    void MainWindow::decorate_dialog(QWidget *widget) {
        BOOL value = TRUE;
        DwmSetWindowAttribute(reinterpret_cast<HWND>(widget->winId()), DWMWA_USE_IMMERSIVE_DARK_MODE, &value, sizeof(value));
    }

    void MainWindow::fill_default_pkcs11_providers() {
        ui->pkcs11_combo_box->addItem("C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll");
    }

    QString MainWindow::pkcs11_provider_dialog_filter() {
        return "PKCS (*.dll *.pem *.pk8 *.p12 *.pfx)";
    }
}