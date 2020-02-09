#include <GUI/MainWindow.h>

#include <QApplication>
#include <QPalette>
#include <QFontDatabase>

static QPalette create_dark_palette() {

    QPalette palette;

    palette.setColor(QPalette::Window, QColor(53, 53, 53));
    palette.setColor(QPalette::WindowText, Qt::white);
    palette.setColor(QPalette::Base, QColor(25, 25, 25));
    palette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
    palette.setColor(QPalette::ToolTipBase, Qt::black);
    palette.setColor(QPalette::ToolTipText, Qt::white);
    palette.setColor(QPalette::Text, Qt::white);
    palette.setColor(QPalette::Button, QColor(53, 53, 53));
    palette.setColor(QPalette::ButtonText, Qt::white);
    palette.setColor(QPalette::BrightText, Qt::red);
    palette.setColor(QPalette::Link, QColor(42, 130, 218));
    palette.setColor(QPalette::Highlight, QColor(42, 130, 218));
    palette.setColor(QPalette::HighlightedText, Qt::white);

    return palette;
}

static QFont get_font() {

    auto font = QFontDatabase::systemFont(QFontDatabase::GeneralFont);

    font.setPixelSize(16);

    return font;
}

int main(int argc, char *argv[]) {

    QApplication app(argc, argv);
    QApplication::setPalette(create_dark_palette());
    QApplication::setFont(get_font());

    GUI::MainWindow w;
    w.show();

    return QApplication::exec();
}
