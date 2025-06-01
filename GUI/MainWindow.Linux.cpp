#include "MainWindow.h"
#include <ui_MainWindow.h>

namespace GUI {

    void MainWindow::decorate_dialog(QWidget *widget) {
    }

    void MainWindow::fill_default_pkcs11_providers() {
        ui->pkcs11_combo_box->addItem("/usr/lib/opensc-pkcs11.so");
        ui->pkcs11_combo_box->addItem("/usr/lib/libeTPkcs11.so");
    }

    QString MainWindow::pkcs11_provider_dialog_filter() {
        return "PKCS (*.so *.pem *.pk8 *.p12 *.pfx)";
    }
}