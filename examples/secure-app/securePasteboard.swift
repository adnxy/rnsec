import UIKit

// SAFE: No sensitive data written to pasteboard - should NOT trigger IOS_INSECURE_PASTEBOARD_USAGE
class SafeCopyHelper {
    func copyShareLink(_ link: String) {
        // Only copying non-sensitive data like share links
        UIPasteboard.general.string = link
    }
}
