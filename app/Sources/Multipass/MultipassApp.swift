import SwiftUI

/// Multipass is a pure menubar app (LSUIElement): a thin, unprivileged UI
/// over `multipassd`, which owns the tunnel.
@main
struct MultipassApp: App {
    @State private var controller = TunnelController()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(controller: controller)
        } label: {
            MenuBarIcon(controller: controller)
        }
        .menuBarExtraStyle(.window)
    }
}

/// The menubar icon mirrors tunnel state through the symbol itself (menu bar
/// rendering is template-only, so tint can't carry state).
private struct MenuBarIcon: View {
    let controller: TunnelController

    private var symbolName: String {
        switch controller.state {
        case .connected:
            if controller.failoverTo != nil {
                // Failover flash in the menu bar: the animated arrows pulse
                // for the duration of the flash.
                return "arrow.triangle.2.circlepath"
            }
            return "point.3.filled.connected.trianglepath.dotted"
        case .transitioning:
            return "arrow.triangle.2.circlepath"
        case .disconnected:
            return "point.3.connected.trianglepath.dotted"
        case .daemonUnavailable:
            return "network.slash"
        }
    }

    var body: some View {
        Image(systemName: symbolName)
            .symbolRenderingMode(.monochrome)
            .contentTransition(.symbolEffect(.replace))
            .symbolEffect(.bounce, value: controller.failoverTo)
    }
}
