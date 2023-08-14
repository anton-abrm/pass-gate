#include "MainWindow.h"
#include <ui_MainWindow.h>

#include <thread>

#include <QMessageBox>
#include <QDebug>
#include <QString>
#include <QWindow>
#include <QTimer>
#include <QSettings>
#include <QFileDialog>
#include <QClipboard>
#include <QDropEvent>
#include <QMimeData>

#include <GUI/PinDialog.h>
#include <PKI/PKCS11Provider.h>
#include <PKI/PKCS12Provider.h>
#include <PKI/PEMProvider.h>
#include <Password/Password.h>
#include <Keyboard/Keyboard.h>
#include <BIP39/BIP39.h>
#include <Crypto/Crypto.h>
#include "Validation/Validation.h"

#include "Core/BIP39EntropySource.h"
#include "Core/BIP39EntropySourceV2.h"
#include "Core/RandomEntropySource.h"
#include "Core/SignatureEntropySourceV2.h"
#include "Core/EncryptionServiceV2.h"
#include "Core/EncryptionServiceV1.h"
#include "Base/Encoding.h"

#include <Version.h>

static const QString c_config_name = "pass-gate";
static const QString c_config_pkcs11_provider = "pkcs11-provider";
static const QString c_config_pinned_public_key_token = "pinned-public-key-token";
static const QString c_config_pinned_public_key_name = "pinned-public-key-name";

static const QString c_map_key_token = "key-token";
static const QString c_map_key_id = "key-id";
static const QString c_map_key_name = "key-name";

static const QChar c_password_separator = u'\u22c5';

static const QString c_save_load_dialog_filter = "Pass Gate Secret (*.pgs)";
static const QString c_select_provider_dialog_filter = "PKCS (*.so *.pem *.pk8 *.p12 *.pfx)";

static const std::size_t c_output_kcv_size = 4;

static std::shared_ptr<Core::PKIProvider> g_provider = PKI::PKCS11Provider::instance();

static QString g_secret_path;

static QString convert_password_to_readable_form(QString password)
{
    if (password.size() == 0)
        return password;

    if (password.contains('\x20'))
        return password;

    if (Validation::is_formatted_guid(password))
        return password;

    QList<int> sizes = {4, 5, 6};

    for (auto size: sizes) {

        if (password.size() % size == 0) {

            QString formatted_secret;

            formatted_secret.reserve(password.size() + password.size() / size - 1);

            for (int i = 0; i < password.size(); ++i) {

                if (i != 0 && i % size == 0)
                    formatted_secret.append(c_password_separator);

                formatted_secret.append(password[i]);
            }

            return formatted_secret;
        }
    }

    return password;
}

static QString convert_password_to_original_from(QString password)
{
    return password.remove(c_password_separator);
}

namespace GUI {

    MainWindow::MainWindow(QWidget *parent)
            : QMainWindow(parent), ui(new Ui::MainWindow) {

        ui->setupUi(this);

#ifdef __APPLE__
        ui->enter_button->setEnabled(false);
#endif

        update_window_title();

        connect(ui->go_button, &QPushButton::clicked, this, &MainWindow::go_button_clicked);
        connect(ui->apply_button, &QPushButton::clicked, this, &MainWindow::apply_button_clicked);
        connect(ui->enter_button, &QPushButton::clicked, this, &MainWindow::enter_button_clicked);
        connect(ui->format_button, &QPushButton::clicked, this, &MainWindow::format_button_clicked);
        connect(ui->pin_key_button, &QPushButton::clicked, this, &MainWindow::pin_key_button_clicked);
        connect(ui->show_secret_button, &QPushButton::toggled, this, &MainWindow::show_secret_button_toggled);
        connect(ui->show_mnemonic_button, &QPushButton::toggled, this, &MainWindow::show_mnemonic_button_toggled);
        connect(ui->mnemonic_line_edit, &QLineEdit::textChanged, this, &MainWindow::mnemonic_line_edit_text_changed);
        connect(ui->copy_secret_button, &QPushButton::toggled, this, &MainWindow::copy_secret_button_toggled);
        connect(ui->secret_line_edit, &QLineEdit::textChanged, this, &MainWindow::secret_line_edit_text_changed);
        connect(ui->secret_line_edit, &QLineEdit::editingFinished, this, &MainWindow::secret_line_edit_editing_finished);
        connect(ui->source_line_edit, &QLineEdit::editingFinished, this, &MainWindow::source_line_edit_editing_finished);
        connect(ui->command_combo_box, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
                this, &MainWindow::command_combo_box_index_changed);

        connect(ui->password_format_combo_box, &QComboBox::currentTextChanged,
                this, &MainWindow::password_format_combo_box_text_changed);

        connect(ui->entropy_type_combo_box, &QComboBox::currentTextChanged,
                this, &MainWindow::entropy_type_combo_box_index_changed);

        connect(ui->clear_data_button, &QPushButton::clicked, this, &MainWindow::clear_data_button_clicked);
        connect(ui->save_data_button, &QPushButton::clicked, this, &MainWindow::save_data_button_clicked);
        connect(ui->load_data_button, &QPushButton::clicked, this, &MainWindow::load_data_button_clicked);

        connect(dynamic_cast<QApplication*>(QApplication::instance()), &QApplication::focusChanged,
                this, &MainWindow::application_focus_changed);

        connect(ui->select_provider_button, &QPushButton::clicked, this, &MainWindow::select_provider_button_clicked);
        connect(ui->data_plain_edit, &QPlainTextEdit::textChanged, this, &MainWindow::data_plain_edit_text_changed);

        this->setWindowFlags(this->windowFlags() | Qt::WindowStaysOnTopHint);

        ui->command_combo_box->addItem("Password", static_cast<int>(Command::Password));
        ui->command_combo_box->addItem("Keyfile", static_cast<int>(Command::Keyfile));
        ui->command_combo_box->addItem("Mnemonic", static_cast<int>(Command::Mnemonic));
        ui->command_combo_box->addItem("Encrypt", static_cast<int>(Command::Encrypt));
        ui->command_combo_box->addItem("Decrypt", static_cast<int>(Command::Decrypt));

        ui->entropy_type_combo_box->addItem("Signature", static_cast<int>(EntropySourceType::Signature));
        ui->entropy_type_combo_box->addItem("BIP39", static_cast<int>(EntropySourceType::BIP39));
        ui->entropy_type_combo_box->addItem("Random", static_cast<int>(EntropySourceType::Random));

        QSettings settings(c_config_name, c_config_name);

        ui->pkcs11_combo_box->setCurrentText(settings.value(c_config_pkcs11_provider).toString());

        ui->data_plain_edit->viewport()->installEventFilter(this);

        reset_key_combo_box(true);
        update_save_button_status();

        auto font = QFontDatabase::systemFont(QFontDatabase::FixedFont);

        font.setPixelSize(16);

        ui->pkcs11_combo_box->setFont(font);
        ui->key_combo_box->setFont(font);
        ui->secret_line_edit->setFont(font);
        ui->source_line_edit->setFont(font);
        ui->source_format_combo_box->setFont(font);
        ui->data_plain_edit->setFont(font);
        ui->mnemonic_line_edit->setFont(font);

        ui->entropy_type_combo_box->setFont(font);
        ui->entropy_format_combo_box->setFont(font);
        ui->command_combo_box->setFont(font);
        ui->password_format_combo_box->setFont(font);
    }

    MainWindow::~MainWindow() {
        QGuiApplication::clipboard()->clear();
        g_provider->terminate();
        delete ui;
    }

    void MainWindow::go_button_clicked() {

        try {

            if (!g_provider->is_initialized())
                apply_provider();

            switch (current_command()) {

                case Command::Password:
                    make_password();
                    break;

                case Command::Keyfile:
                    make_keyfile();
                    break;

                case Command::Encrypt:
                    encrypt();
                    break;

                case Command::Decrypt:
                    decrypt();
                    break;

                case Command::Mnemonic:
                    make_mnemonic();
                    break;
            }

            this->ui->go_button->setText("Done");

            QTimer::singleShot(750, this, [this](){
                this->ui->go_button->setText("Run");
            });
        }
        catch (const std::exception &ex) {
            QMessageBox::warning(this, "Error", ex.what());
        }
    }

    void MainWindow::mnemonic_line_edit_text_changed() {

        auto entropy = BIP39::mnemonic_to_entropy(ui->mnemonic_line_edit->text().toStdString());

        if (entropy)
        {
            QPalette palette = ui->show_mnemonic_button->palette();
            palette.setColor(QPalette::Button, QColor(45, 107, 51));
            ui->show_mnemonic_button->setPalette(palette);

            ui->show_mnemonic_button->setText(QString::number(entropy.value().size() * 8) + " bit");
        }
        else
        {
            ui->show_mnemonic_button->setText("Show");

            QPalette palette = ui->show_mnemonic_button->palette();
            palette.setColor(QPalette::Button, QApplication::palette().color(QPalette::Button));
            ui->show_mnemonic_button->setPalette(palette);

            ui->show_mnemonic_button->setPalette(QApplication::palette());
        }
    }

    void MainWindow::enter_button_clicked()
    {
        auto secret = convert_password_to_original_from(ui->secret_line_edit->text());

        std::thread([=](){
            Keyboard::enter_text(secret.toStdString());
        }).detach();
    }

    std::unique_ptr<MainWindow::EntropyContext> MainWindow::create_entropy_context() const
    {
        auto entropy = std::make_unique<EntropyContext>();

        std::string info;

        switch (current_command())
        {
            case Command::Encrypt:
            case Command::Decrypt:
                info = "encryption";
                break;

            case Command::Keyfile:
                info = "keyfile";
                break;

            case Command::Password:
                info = "password";
                break;

            case Command::Mnemonic:
                info = "mnemonic";
                break;
        }

        switch (current_entropy_type())
        {
            case EntropySourceType::Random:
            {
                entropy->entropy_id = "rand";
                entropy->source = std::make_unique<Core::RandomEntropySource>(g_provider);
                break;
            }

            case EntropySourceType::BIP39:
            {
                const auto mnemonic = ui->mnemonic_line_edit->text().toStdString();

                const auto mnemonic_entropy = BIP39::mnemonic_to_entropy(mnemonic);

                if (!mnemonic_entropy)
                    throw std::runtime_error("Invalid mnemonic");

                const auto hash = Crypto::compute_sha_256(mnemonic_entropy.value());

                const auto bip39_version = current_bip39_version();

                entropy->entropy_id.append("bip39-v");
                entropy->entropy_id.append(std::to_string(static_cast<int>(bip39_version)));
                entropy->entropy_id.append("-");
                entropy->entropy_id.append(Base::Encoding::encode_hex_lower({hash.data(), c_output_kcv_size}));

                switch (bip39_version)
                {
                    case BIP39Version::BIP39V1:
                        entropy->source = std::make_unique<Core::BIP39EntropySource>(mnemonic);
                        break;

                    case BIP39Version::BIP39V2:
                        entropy->source = std::make_unique<Core::BIP39EntropySourceV2>(mnemonic, info);
                        break;
                }

                break;
            }

            case EntropySourceType::Signature:
            {
                if (ui->key_combo_box->currentIndex() == 0)
                    throw std::runtime_error("The certificate is not selected");

                const auto id = ui->key_combo_box->currentData()
                        .toMap()
                        .value(c_map_key_id)
                        .toByteArray();

                const auto token = ui->key_combo_box->currentData()
                        .toMap()
                        .value(c_map_key_token)
                        .toByteArray();

                const auto sign_version = current_signature_version();

                entropy->entropy_id.append("sign-v");
                entropy->entropy_id.append(std::to_string(static_cast<int>(sign_version)));
                entropy->entropy_id.append("-");
                entropy->entropy_id.append(
                        Base::Encoding::encode_hex_lower(
                                {reinterpret_cast<const uint8_t *>(token.data()), c_output_kcv_size}));

                switch (sign_version)
                {
                    case SignatureVersion::SignatureV2:

                        entropy->source = std::make_unique<Core::SignatureEntropySourceV2>(
                                g_provider,
                                std::span<const uint8_t>(
                                        reinterpret_cast<const uint8_t *>(id.data()), id.size()),
                                info);

                        break;
                }

                break;
            }

            default:
                throw std::logic_error("Unsupported entropy source.");
        }

        return entropy;
    }

    void MainWindow::make_password() {

        const auto nonce = ui->source_line_edit->text().toStdString();

        switch (current_entropy_type())
        {
            case EntropySourceType::Random:
                break;

            case EntropySourceType::Signature:
            case EntropySourceType::BIP39:
                if (nonce.empty() && !prompt_warning_yes_no("Do you really want to use the empty salt?"))
                    return;
                break;
        }

        const auto source = create_entropy_context()->source;

        const auto seed = source->get_seed(
                nonce, std::min(source->max_seed_size(), static_cast<std::size_t>(128)));

        const auto format = ui->password_format_combo_box->currentText().toLatin1();

        int index{0};
        auto password = Password::generate(format.constData(), [&]() -> int16_t {
            return index < seed.size()
                   ? static_cast<int16_t>(seed.at(index++))
                   : static_cast<int16_t>(-1);
        });

        ui->secret_line_edit->setText(
                QString::fromUtf8(password.data(), static_cast<int>(password.size())));

        format_password();
    }

    void MainWindow::make_keyfile() {

        const auto nonce = ui->source_line_edit->text().toStdString();

        switch (current_entropy_type())
        {
            case EntropySourceType::Random:
                break;

            case EntropySourceType::Signature:
            case EntropySourceType::BIP39:
                if (nonce.empty() && !prompt_warning_yes_no("Do you really want to use the empty salt?"))
                    return;
                break;
        }

        const auto keyfile_size =
                static_cast<std::size_t>(ui->password_format_combo_box->currentData().toInt());

        const auto seed = create_entropy_context()->source->get_seed(nonce, keyfile_size);

        const auto hash_hex = Base::Encoding::encode_hex_lower(
                Crypto::compute_sha_256(seed));

        const auto file_name = QString::fromUtf8(hash_hex.data(), 8) + ".keyfile";

        auto fileName = QFileDialog::getSaveFileName(this, "Save Keyfile", file_name);
        if (fileName.isEmpty())
            return;

        QFile file(fileName);

        if (!file.open(QIODevice::WriteOnly))
            throw std::runtime_error("Unable to open the file for saving.");

        if (file.write(reinterpret_cast<const char *>(seed.data()), static_cast<qint64>(seed.size())) != seed.size())
            throw std::runtime_error("An error occurred while writing the keyfile.");
    }

    void MainWindow::make_mnemonic() {

        const auto nonce = ui->source_line_edit->text().toStdString();

        switch (current_entropy_type())
        {
            case EntropySourceType::Random:
                break;

            case EntropySourceType::Signature:
            case EntropySourceType::BIP39:
                if (nonce.empty() && !prompt_warning_yes_no("Do you really want to use the empty salt?"))
                    return;
                break;
        }

        const auto mnemonic_size =
                static_cast<std::size_t>(ui->password_format_combo_box->currentData().toInt());

        const auto seed = create_entropy_context()->source->get_seed(nonce, mnemonic_size);

        const auto mnemonic = BIP39::entropy_to_mnemonic(seed).value();

        ui->secret_line_edit->setText(QString::fromUtf8(
                mnemonic.data(), static_cast<QString::size_type >(mnemonic.size())));
    }

    void MainWindow::save_data_button_clicked() {

        auto file_name = g_secret_path;

        if (file_name.isEmpty())
            file_name = QFileDialog::getSaveFileName(this, "Save Secret", QString(), c_save_load_dialog_filter);

        if (file_name.isEmpty())
            return;

        QString text;

        text.append(ui->data_plain_edit->toPlainText().trimmed());
        text.append('\n');

        const auto bytes = text.toUtf8();

        QFile file(file_name);

        if (!file.open(QIODevice::WriteOnly))
            throw std::runtime_error("Unable to open the file for saving.");

        if (file.write(bytes.data(), bytes.size()) != bytes.size())
            throw std::runtime_error("An error occurred while writing the keyfile.");

        g_secret_path = file_name;

        update_window_title();

        this->ui->save_data_button->setText("Done");

        QTimer::singleShot(750, this, [this](){
            this->ui->save_data_button->setText("Save");
        });
    }

    std::unique_ptr<Core::EncryptionService> MainWindow::create_encryption_service(
            EncryptionVersion version,
            std::shared_ptr<Core::EntropySource> source) const {

        const auto salt = ui->source_line_edit->text().toStdString();

        switch (version)
        {

            case EncryptionVersion::EncryptionV2:
                return std::make_unique<Core::EncryptionServiceV2>(std::move(source), g_provider, salt);

            case EncryptionVersion::EncryptionV1:
                return std::make_unique<Core::EncryptionServiceV1>(std::move(source), g_provider, salt);

            default:
                throw std::invalid_argument("version is out of range");
        }
    }

    void MainWindow::encrypt() {

        auto data = convert_password_to_original_from(
                ui->secret_line_edit->text()).toStdString();

        if (data.empty() && !prompt_warning_yes_no("Do you really want to encrypt the empty data?"))
            return;

        const auto enc_version = static_cast<EncryptionVersion>(ui->password_format_combo_box->currentData().toInt());

        switch (current_entropy_type())
        {
            case EntropySourceType::Random:
                if (!prompt_warning_yes_no("Do you really want to encrypt by using the random entropy?"))
                    return;
                break;

            case EntropySourceType::Signature:
            case EntropySourceType::BIP39:
            {
                switch (enc_version)
                {
                    case EncryptionVersion::EncryptionV1:
                        if (ui->source_line_edit->text().isEmpty() &&
                            !prompt_warning_yes_no("Do you really want to encrypt the secret without the salt?\n"
                                                   "The ciphers will be the same for the same passwords.")) {
                            return;
                        }

                        break;
                    case EncryptionVersion::EncryptionV2:

                        if (!ui->source_line_edit->text().isEmpty() &&
                            !prompt_warning_yes_no("Do you really want to encrypt the secret with the salt?\n"
                                                   "You will have to enter it upon the decryption.")) {
                            return;
                        }
                        break;
                }

                break;
            }
        }

        const auto ctx = create_entropy_context();

        const auto service = create_encryption_service(enc_version, ctx->source);

        const auto body = service->encrypt(data);

        std::string msg;

        msg.append("pgs-v1");
        msg.append(".");
        msg.append(ctx->entropy_id);
        msg.append(".");
        msg.append("enc-v");
        msg.append(std::to_string(static_cast<int>(enc_version)));
        msg.append(".");
        msg.append(Base::Encoding::encode_base64_url_no_padding(body));

        ui->data_plain_edit->setPlainText(
                QString::fromStdString(msg));
    }

    void MainWindow::decrypt() {

        const auto message = ui->data_plain_edit->toPlainText().trimmed();

        EncryptionVersion version;
        QString body_base64;

        const auto sections = message.split(".");

        if (sections.size() == 4)
        {
            auto version_str = sections.at(2);

            if (!version_str.startsWith("enc-v"))
                throw std::runtime_error("Invalid format.");

            version_str.remove(0, 5);

            version = static_cast<EncryptionVersion>(version_str.toInt());

            if (version < EncryptionVersion::EncryptionV1 ||
                version > EncryptionVersion::EncryptionV2)
                    throw std::runtime_error("Invalid format.");

            body_base64 = sections.at(3);
        }
        else
        {
            version = EncryptionVersion::EncryptionV1;
            body_base64 = message;
        }

        const auto body = Base::Encoding::decode_base64_any(body_base64.toStdString());

        const auto encryption_service = create_encryption_service(version, create_entropy_context()->source);

        const auto data = encryption_service->decrypt(body);

        ui->secret_line_edit->setText(
                QString::fromUtf8(
                        data.data(), static_cast<int>(data.size())));
    }

    void MainWindow::apply_button_clicked() {

        apply_provider();

        this->ui->apply_button->setText("Done");

        QTimer::singleShot(750, this, [this](){
            this->ui->apply_button->setText("Apply");
        });
    }

    void MainWindow::update_certificates() {

        const auto saved_token = ui->key_combo_box->currentData()
                .toMap()
                .value(c_map_key_token)
                .toByteArray();

        reset_key_combo_box(false);

        auto certificates = g_provider->get_certificates();

        for (const auto &certificate: certificates) {

            const auto key_token = QByteArray(
                    reinterpret_cast<QByteArray::value_type *>(certificate.public_key_token().data()),
                    static_cast<QByteArray::size_type>(certificate.public_key_token().size()));

            const auto key_id = QByteArray(
                    reinterpret_cast<QByteArray::value_type *>(certificate.id().data()),
                    static_cast<QByteArray::size_type>(certificate.id().size()));

            const auto key_name = QString::fromStdString(certificate.common_name());

            QString text;

            text.append(key_token.mid(0, 4).toHex());
            text.append(" | ");
            text.append(key_name);

            QMap<QString, QVariant> data;

            data[c_map_key_token] = key_token;
            data[c_map_key_id] = key_id;
            data[c_map_key_name] = key_name;

            ui->key_combo_box->addItem(text, data);
        }

        for (int i = 0; i < ui->key_combo_box->count(); ++i)
        {
           const auto token = ui->key_combo_box->itemData(i)
                    .toMap()
                    .value(c_map_key_token)
                    .toByteArray();

            if (token == saved_token) {
                ui->key_combo_box->setCurrentIndex(i);
                break;
            }
        }

        if (ui->key_combo_box->currentIndex() == -1)
            ui->key_combo_box->setCurrentIndex(0);
    }

    static std::shared_ptr<Core::PKIProvider> get_provider(const QString& provider_path) {

        if (provider_path.endsWith(".pem", Qt::CaseSensitivity::CaseInsensitive) ||
            provider_path.endsWith(".pk8", Qt::CaseSensitivity::CaseInsensitive))
                return PKI::PEMProvider::instance();

        if (provider_path.endsWith(".pfx", Qt::CaseSensitivity::CaseInsensitive) ||
            provider_path.endsWith(".p12", Qt::CaseSensitivity::CaseInsensitive))
                return PKI::PKCS12Provider::instance();

        return PKI::PKCS11Provider::instance();
    }

    void MainWindow::apply_provider() {

        // A segmentation fault error is thrown while
        // enumerating certificates for the second time
        // with use of the opensc-pkcs11 provider. To handle
        // this issue the reinitialization procedure is performed by
        // calling terminate and initialize functions respectively.

        g_provider->terminate();

        const auto provider_path = ui->pkcs11_combo_box->currentText().trimmed();

        if (!provider_path.isEmpty()) {
            try {

                g_provider = get_provider(provider_path);

                g_provider->set_pin_callback([this](std::string &pin) -> bool {

                    PinDialog dlg(this);

                    dlg.setModal(true);

                    if (!dlg.exec())
                        return false;

                    pin = dlg.pin().toStdString();

                    return true;
                });

                g_provider->set_slot_callback([this]() {
                    QTimer::singleShot(0, this, &MainWindow::update_certificates);
                });

                g_provider->initialize(provider_path.toStdString());
            }
            catch (const std::exception &ex) {
                QMessageBox::warning(this, "Error", ex.what());
                return;
            }

            update_certificates();
        }

        QSettings settings(c_config_name, c_config_name);

        settings.setValue(c_config_pkcs11_provider, ui->pkcs11_combo_box->currentText());
    }

    void MainWindow::pin_key_button_clicked() {

        QSettings settings(c_config_name, c_config_name);

        const auto map = ui->key_combo_box->currentData().toMap();

        const auto key_token = map.value(c_map_key_token).toByteArray();
        const auto key_name = map.value(c_map_key_name).toString();

        settings.setValue(c_config_pinned_public_key_token, key_token);
        settings.setValue(c_config_pinned_public_key_name, key_name);

        this->ui->pin_key_button->setText("Done");

        QTimer::singleShot(750, this, [this](){
            this->ui->pin_key_button->setText("Pin");
        });
    }

    void MainWindow::format_button_clicked() {

        auto text = ui->source_line_edit->text();

        for (const auto symbol : ui->source_format_combo_box->currentText()) {

            switch (symbol.toLatin1()) {

                case 'l':
                    text = text.toLower();
                    break;

                case 't':
                    text = text.trimmed();
                    break;

                case 's': {

                    int i = 0;
                    for (auto ch : text)
                        if (!ch.isSpace())
                            text[i++] = ch;

                    text.resize(i);
                    break;
                }
            }
        }

        ui->source_line_edit->setText(text);
    }

    void MainWindow::show_secret_button_toggled(bool checked)
    {
        static uint32_t seconds {0};
        static QTimer * timer = nullptr;
        static QString text;

        if (!timer) {
            timer = new QTimer(this);
            connect(timer, &QTimer::timeout, this, [this]{
                if (seconds > 1) {
                    seconds--;
                    this->ui->show_secret_button->setText(QString::number(seconds));
                }
                else
                {
                    ui->show_secret_button->setChecked(false);
                }
            });
        }

        if (checked)
        {
            text = ui->show_secret_button->text();

            show_secret();

            seconds = 60;
            ui->show_secret_button->setText(QString::number(seconds));

            if (!timer->isActive())
                timer->start(1000);
        }
        else
        {
            hide_secret();
            ui->show_secret_button->setText(text);

            if (timer->isActive())
                timer->stop();
        }
    }

    void MainWindow::format_password()
    {
        const auto old_secret = ui->secret_line_edit->text();

        auto secret = convert_password_to_original_from(old_secret);
        if (ui->secret_line_edit->echoMode() == QLineEdit::EchoMode::Normal)
            secret = convert_password_to_readable_form(secret);

        QString::size_type stripped_cursor_position = 0;

        for (QString::size_type i = 0; i < ui->secret_line_edit->cursorPosition(); i++)
        {
            if (old_secret[i] != c_password_separator)
                stripped_cursor_position++;
        }

        QString::size_type cursor_position = 0;

        for (QString::size_type i = 0; i < stripped_cursor_position; )
        {
            if (secret[cursor_position] != c_password_separator)
                i++;

            cursor_position++;
        }

        ui->secret_line_edit->blockSignals(true);
        ui->secret_line_edit->setText(secret);
        ui->secret_line_edit->blockSignals(false);

        ui->secret_line_edit->setCursorPosition(cursor_position);
    }

    void MainWindow::show_secret()
    {
        ui->secret_line_edit->setEchoMode(QLineEdit::EchoMode::Normal);

        format_password();
    }

    void MainWindow::hide_secret()
    {
        ui->secret_line_edit->setEchoMode(QLineEdit::EchoMode::Password);

        format_password();
    }

    void MainWindow::copy_secret_button_toggled(bool checked)
    {
        static uint32_t seconds {0};
        static QTimer * timer = nullptr;
        static QString text;

        if (!timer) {
            timer = new QTimer(this);
            connect(timer, &QTimer::timeout, this, [this]{
                if (seconds > 1) {
                    seconds--;
                    this->ui->copy_secret_button->setText(QString::number(seconds));
                }
                else
                {
                    ui->copy_secret_button->setChecked(false);
                }
            });
        }

        if (checked)
        {
            text = ui->copy_secret_button->text();

            QApplication::clipboard()->setText(
                    convert_password_to_original_from(
                            ui->secret_line_edit->text()));

            seconds = 15;
            ui->copy_secret_button->setText(QString::number(seconds));

            if (!timer->isActive())
                timer->start(1000);
        }
        else
        {
            QApplication::clipboard()->clear();

            ui->copy_secret_button->setText(text);

            if (timer->isActive())
                timer->stop();
        }
    }

    void MainWindow::secret_line_edit_text_changed() {
        format_password();
    }

    void MainWindow::command_combo_box_index_changed()
    {
        static std::optional<Command> last_command;
        static std::map<Command, QString> last_values;

        if (last_command)
            last_values[last_command.value()] = ui->password_format_combo_box->currentText();

        const auto command = this->current_command();

        switch (command)
        {
            case Command::Password:
                reset_format_combo_box_for_password();
                break;

            case Command::Keyfile:
                reset_format_combo_box_for_keyfile();
                break;

            case Command::Mnemonic:
                reset_format_combo_box_for_mnemonic();
                break;

            case Command::Encrypt:
                reset_format_combo_box_for_encryption();
                break;

            case Command::Decrypt:
                reset_format_combo_box_for_decryption();
                break;
        }

        if (last_values.contains(command))
            ui->password_format_combo_box->setCurrentText(last_values[command]);

        last_command = command;
    }

    void MainWindow::show_mnemonic_button_toggled(bool checked)
    {
        static uint32_t seconds {0};
        static QTimer * timer = nullptr;

        if (!timer) {
            timer = new QTimer(this);
            connect(timer, &QTimer::timeout, this, [this]{
                if (seconds > 1) {
                    seconds--;
                    this->ui->show_mnemonic_button->setText(QString::number(seconds));
                }
                else
                {
                    ui->show_mnemonic_button->setChecked(false);
                }
            });
        }

        if (checked)
        {
            ui->mnemonic_line_edit->setEchoMode(QLineEdit::EchoMode::Normal);

            seconds = 60;
            ui->show_mnemonic_button->setText(QString::number(seconds));

            if (!timer->isActive())
                timer->start(1000);
        }
        else
        {
            ui->mnemonic_line_edit->setEchoMode(QLineEdit::EchoMode::Password);

            mnemonic_line_edit_text_changed();

            if (timer->isActive())
                timer->stop();
        }
    }

    void MainWindow::source_line_edit_editing_finished()
    {
        ui->source_line_edit->setText(ui->source_line_edit->text().trimmed());
    }

    void MainWindow::clear_data_button_clicked()
    {
        ui->data_plain_edit->clear();
        g_secret_path.clear();
        update_window_title();
    }

    void MainWindow::application_focus_changed(QWidget *old)
    {
        if (old == ui->data_plain_edit) {
            ui->data_plain_edit->setPlainText(
                    ui->data_plain_edit->toPlainText().trimmed());
        }
    }

    void MainWindow::load_data_button_clicked()
    {
        auto file_path = QFileDialog::getOpenFileName(this, "Open Secret", QString(), c_save_load_dialog_filter);
        if (file_path.isEmpty())
            return;

        try {
            load_secret_file(file_path);
        }
        catch (const std::runtime_error& ex) {
            QMessageBox::warning(this, "Error", ex.what());
        }
    }

    void MainWindow::secret_line_edit_editing_finished()
    {
        ui->secret_line_edit->setText(
                ui->secret_line_edit->text().trimmed());
    }

    bool MainWindow::eventFilter(QObject *obj, QEvent *event) {

        if (obj != ui->data_plain_edit->viewport() || event->type() != QEvent::Drop)
            return false;

        const auto drop_event = dynamic_cast<QDropEvent*>(event);

        const QString prefix = "file://";

        if (!drop_event->mimeData()->hasText() ||
            !drop_event->mimeData()->text().startsWith(prefix))
            return true;

        const auto file_path = drop_event->mimeData()->text()
                .remove(0, prefix.length())
                .trimmed();

        try {
            load_secret_file(file_path);
        }
        catch (const std::runtime_error& ex) {
            QMessageBox::warning(this, "Error", ex.what());
            return true;
        }

        event->setAccepted(true);

        return true;
    }

    void MainWindow::update_window_title() {

        if (g_secret_path.isEmpty()) {

            QString title;

            title.append("Pass Gate v");
            title.append(CMAKE_PROJECT_VERSION);
            title.append(".");
            title.append(GIT_COMMITS);
            title.append("+");
            title.append(GIT_HASH);
            title.append(GIT_DIRTY);

            this->setWindowTitle(title);
        }
        else{
            this->setWindowTitle(QFileInfo(g_secret_path).fileName());
        }
    }

    void MainWindow::select_provider_button_clicked()
    {
        const auto file_name = QFileDialog::getOpenFileName(
                this, "Open Secret", QString(), c_select_provider_dialog_filter);

        if (file_name.isEmpty())
            return;

        ui->pkcs11_combo_box->setCurrentText(file_name);
    }

    void MainWindow::reset_key_combo_box(bool append_pinned)
    {
        ui->key_combo_box->clear();
        ui->key_combo_box->addItem("<none>", QMap<QString, QVariant>());

        if (!append_pinned)
            return;

        QSettings settings(c_config_name, c_config_name);

        const auto key_token = settings.value(c_config_pinned_public_key_token).toByteArray();

        if (key_token.isEmpty())
            return;

        const auto key_name = settings.value(c_config_pinned_public_key_name).toByteArray();

        QMap<QString, QVariant> data;

        data[c_map_key_token] = key_token;
        data[c_map_key_name] = key_name;

        QString text;

        text.append(key_token.mid(0, 4).toHex());
        text.append(" | ");

        if (!key_name.isEmpty())
        {
            text.append(key_name);
            text.append(" ");
        }

        text.append("(Cached)");

        ui->key_combo_box->addItem(text, data);

        ui->key_combo_box->setCurrentIndex(1);
    }

    void MainWindow::load_secret_file(const QString &file_path)
    {
        QFile file(file_path);

        if (!file.open(QIODevice::ReadOnly))
            throw std::runtime_error("Unable to open the file.");

        if (file.size() > 1024)
            throw std::runtime_error("The file is too large.");

        QTextStream stream(&file);

        ui->data_plain_edit->setPlainText(
                stream.readAll().trimmed());

        g_secret_path = file_path;

        update_window_title();
    }

    void MainWindow::update_save_button_status()
    {
        if (ui->data_plain_edit->toPlainText().trimmed().isEmpty())
        {
            QPalette palette = ui->save_data_button->palette();
            palette.setColor(QPalette::ButtonText, Qt::darkGray);
            ui->save_data_button->setPalette(palette);

            ui->save_data_button->setEnabled(false);
        }
        else
        {
            ui->save_data_button->setEnabled(true);

            QPalette palette = ui->save_data_button->palette();
            palette.setColor(QPalette::ButtonText, QApplication::palette().color(QPalette::ButtonText));
            ui->save_data_button->setPalette(palette);
        }
    }

    void MainWindow::data_plain_edit_text_changed()
    {
        update_save_button_status();
    }

    bool MainWindow::prompt_warning_yes_no(const QString &text)
    {
        QMessageBox mb(this);

        mb.setIcon(QMessageBox::Warning);
        mb.setWindowTitle("Warning");
        mb.setText(text);
        mb.setStandardButtons(QMessageBox::Yes | QMessageBox::No);

        return mb.exec() == QMessageBox::Yes;
    }

    MainWindow::Command MainWindow::current_command() const
    {
        return static_cast<Command>(ui->command_combo_box->currentData().toInt());
    }

    MainWindow::EntropySourceType MainWindow::current_entropy_type() const
    {
       return static_cast<EntropySourceType>(ui->entropy_type_combo_box->currentData().toInt());
    }

    void MainWindow::reset_format_combo_box_for_password()
    {
        ui->password_format_combo_box->clear();

        ui->password_format_combo_box->addItem("16hhhs");
        ui->password_format_combo_box->addItem("24hhhs");
        ui->password_format_combo_box->addItem("32hhhs");
        ui->password_format_combo_box->addItem("04xxax");
        ui->password_format_combo_box->addItem("08xxax");
        ui->password_format_combo_box->addItem("08_hex");
        ui->password_format_combo_box->addItem("16_hex");
        ui->password_format_combo_box->addItem("32_hex");

        ui->password_format_combo_box->setEditable(true);
    }

    void MainWindow::reset_format_combo_box_for_keyfile()
    {
        ui->password_format_combo_box->clear();

        ui->password_format_combo_box->addItem("512 bit", 64);
        ui->password_format_combo_box->addItem("256 bit", 32);
        ui->password_format_combo_box->addItem("128 bit", 16);

        ui->password_format_combo_box->setEditable(false);
    }

    void MainWindow::reset_format_combo_box_for_mnemonic()
    {
        ui->password_format_combo_box->clear();

        ui->password_format_combo_box->addItem("128 bit", 16);
        ui->password_format_combo_box->addItem("92 bit", 12);
        ui->password_format_combo_box->addItem("64 bit", 8);

        ui->password_format_combo_box->setEditable(false);
    }

    void MainWindow::reset_format_combo_box_for_encryption()
    {
        ui->password_format_combo_box->clear();
        ui->password_format_combo_box->addItem("v2 (Latest)", static_cast<int>(EncryptionVersion::EncryptionV2));
        ui->password_format_combo_box->addItem("v1", static_cast<int>(EncryptionVersion::EncryptionV1));
        ui->password_format_combo_box->setEditable(false);
    }

    void MainWindow::reset_format_combo_box_for_decryption()
    {
        ui->password_format_combo_box->clear();
        ui->password_format_combo_box->addItem("Auto");
        ui->password_format_combo_box->setEditable(false);
    }

    void MainWindow::password_format_combo_box_text_changed()
    {
        QString text = "pa$$word";

        if (current_command() == Command::Password) {

            const auto entropy = Password::calculate_entropy(
                    ui->password_format_combo_box->currentText().toStdString());

            if (entropy) {
                text.append(" (");
                text.append(QString::number(entropy.value()));
                text.append(" bit)");
            }
        }

        ui->secret_line_edit->setPlaceholderText(text);
    }

    MainWindow::SignatureVersion MainWindow::current_signature_version() const
    {
        return static_cast<SignatureVersion>(ui->entropy_format_combo_box->currentData().toInt());
    }

    MainWindow::BIP39Version MainWindow::current_bip39_version() const
    {
        return static_cast<BIP39Version>(ui->entropy_format_combo_box->currentData().toInt());
    }

    void MainWindow::reset_format_combo_box_for_signature()
    {
        ui->entropy_format_combo_box->clear();
        ui->entropy_format_combo_box->addItem("v2 (Latest)", static_cast<int>(SignatureVersion::SignatureV2));
    }

    void MainWindow::reset_format_combo_box_for_bip39()
    {
        ui->entropy_format_combo_box->clear();
        ui->entropy_format_combo_box->addItem("v2 (Latest)", static_cast<int>(BIP39Version::BIP39V2));
        ui->entropy_format_combo_box->addItem("v1", static_cast<int>(BIP39Version::BIP39V1));
    }

    void MainWindow::reset_format_combo_box_for_random()
    {
        ui->entropy_format_combo_box->clear();
        ui->entropy_format_combo_box->addItem("Auto");
    }

    void MainWindow::entropy_type_combo_box_index_changed()
    {
        static std::optional<EntropySourceType> last_entropy_type;
        static std::map<EntropySourceType, QString> last_values;

        if (last_entropy_type)
            last_values[last_entropy_type.value()] = ui->entropy_format_combo_box->currentText();

        const auto entropy_type = current_entropy_type();

        switch (entropy_type)
        {
            case EntropySourceType::Signature:
                reset_format_combo_box_for_signature();
                break;

            case EntropySourceType::BIP39:
                reset_format_combo_box_for_bip39();
                break;

            case EntropySourceType::Random:
                reset_format_combo_box_for_random();
                break;
        }

        if (last_values.contains(entropy_type))
            ui->entropy_format_combo_box->setCurrentText(last_values[entropy_type]);

        last_entropy_type = entropy_type;
    }
}
