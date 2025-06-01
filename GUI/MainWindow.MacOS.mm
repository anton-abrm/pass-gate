#include "MainWindow.h"
#include <ui_MainWindow.h>

#include <QWidget>

#include <Cocoa/Cocoa.h>

namespace GUI {

    void MainWindow::decorate_dialog(QWidget *widget) {

        auto * view = (NSView*) widget->winId();

        NSWindow* window = [view window];
        [window setTitlebarAppearsTransparent:true];
        [window setBackgroundColor: [NSColor colorWithRed:53./255. green:53./255. blue:53./255. alpha:1.]];
    }

    void MainWindow::fill_default_pkcs11_providers() {
        ui->pkcs11_combo_box->addItem("/Library/OpenSC/lib/opensc-pkcs11.so");
    }

    QString MainWindow::pkcs11_provider_dialog_filter() {
        return "PKCS (*.so *.dylib *.pem *.pk8 *.p12 *.pfx)";
    }
}