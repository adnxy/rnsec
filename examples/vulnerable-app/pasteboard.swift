import UIKit

// IOS_INSECURE_PASTEBOARD_USAGE - Rule should detect this
class PasswordCopyHelper {
    func copyPassword(_ password: String) {
        // Copying sensitive credential to pasteboard - accessible by all apps
        UIPasteboard.general.string = password
    }

    func copyToken(_ token: String) {
        UIPasteboard.general.string = token
    }
}
