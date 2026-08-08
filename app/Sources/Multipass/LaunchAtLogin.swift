import Foundation
import ServiceManagement

/// Thin wrapper around `SMAppService.mainApp`, same shape as baratheon's.
enum LaunchAtLogin {
    /// `SMAppService.mainApp.register()` requires a properly bundled,
    /// LaunchServices-resolvable app; a raw SPM executable (`swift run`,
    /// `.build/.../Multipass`) never satisfies this and must not be confused
    /// with the ordinary `.notRegistered` production state.
    static var isRunningAsAppBundle: Bool {
        Bundle.main.bundleURL.pathExtension == "app"
    }

    static var status: SMAppService.Status {
        SMAppService.mainApp.status
    }

    static func register() throws {
        try SMAppService.mainApp.register()
    }

    static func unregister() throws {
        try SMAppService.mainApp.unregister()
    }

    static func openSystemSettingsLoginItems() {
        SMAppService.openSystemSettingsLoginItems()
    }
}
