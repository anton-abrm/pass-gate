#pragma once

#include <QMainWindow>
#include <Base/ZVector.h>
#include "Core/EntropySource.h"
#include "Core/EncryptionService.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

namespace GUI {

    class MainWindow : public QMainWindow {
    Q_OBJECT

    public:
        explicit MainWindow(QWidget *parent = nullptr);
        ~MainWindow() override;

    protected:
        bool eventFilter(QObject *obj, QEvent *event) override;

    private:

        enum class SignatureVersion {
            SignatureV2 = 2,
        };

        enum class BIP39Version {
            BIP39V1 = 1,
            BIP39V2 = 2,
        };

        enum class EncryptionVersion {
            EncryptionV1 = 1,
            EncryptionV2 = 2,
        };

        enum class EntropySourceType {
            Signature,
            BIP39,
            Random,
        };

        enum class Command {
            Encrypt,
            Decrypt,
            Keyfile,
            Password,
            Mnemonic
        };

        typedef struct {
            std::string entropy_id;
            std::shared_ptr<Core::EntropySource> source;
        } EntropyContext;

        [[nodiscard]] inline EntropySourceType current_entropy_type() const;
        [[nodiscard]] inline SignatureVersion current_signature_version() const;
        [[nodiscard]] inline BIP39Version current_bip39_version() const;
        [[nodiscard]] inline Command current_command() const;

        [[nodiscard]] std::unique_ptr<EntropyContext> create_entropy_context() const;
        [[nodiscard]] std::unique_ptr<Core::EncryptionService> create_encryption_service(
                EncryptionVersion version,
                std::shared_ptr<Core::EntropySource> source) const;

        void apply_provider();
        void update_certificates();

        void encrypt();
        void decrypt();
        void make_keyfile();
        void make_password();
        void make_mnemonic();
        void format_password();

        void show_secret();
        void hide_secret();

        void update_window_title();
        void update_save_button_status();
        void reset_key_combo_box(bool append_pinned);
        void load_secret_file(const QString &file_path);
        bool prompt_warning_yes_no(const QString &text);

        void reset_format_combo_box_for_password();
        void reset_format_combo_box_for_keyfile();
        void reset_format_combo_box_for_mnemonic();
        void reset_format_combo_box_for_encryption();
        void reset_format_combo_box_for_decryption();

        void reset_format_combo_box_for_signature();
        void reset_format_combo_box_for_bip39();
        void reset_format_combo_box_for_random();

    private slots:

        void pin_key_button_clicked();
        void go_button_clicked();
        void apply_button_clicked();
        void show_secret_button_toggled(bool checked);
        void show_mnemonic_button_toggled(bool checked);
        void enter_button_clicked();
        void format_button_clicked();
        void mnemonic_line_edit_text_changed();
        void copy_secret_button_toggled(bool checked);
        void secret_line_edit_text_changed();
        void secret_line_edit_editing_finished();
        void source_line_edit_editing_finished();
        void command_combo_box_index_changed();
        void password_format_combo_box_text_changed();
        void application_focus_changed(QWidget *old);
        void save_data_button_clicked();
        void clear_data_button_clicked();
        void load_data_button_clicked();
        void select_provider_button_clicked();
        void data_plain_edit_text_changed();
        void entropy_type_combo_box_index_changed();

    private:
        Ui::MainWindow *ui;
    };
}
