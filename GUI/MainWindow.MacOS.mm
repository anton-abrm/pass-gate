#include "MainWindow.h"

#include <QWidget>

#include <Cocoa/Cocoa.h>

namespace GUI {

    void MainWindow::decorate_dialog(QWidget *widget) {

        auto * view = (NSView*) widget->winId();

        NSWindow* window = [view window];
        [window setTitlebarAppearsTransparent:true];
        [window setBackgroundColor: [NSColor colorWithRed:53./255. green:53./255. blue:53./255. alpha:1.]];
    }
}