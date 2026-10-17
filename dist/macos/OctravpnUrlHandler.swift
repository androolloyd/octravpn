import AppKit
import Carbon
import Foundation

final class OctravpnUrlHandler: NSObject, NSApplicationDelegate {
    @objc func handleGetURL(_ event: NSAppleEventDescriptor, withReplyEvent _: NSAppleEventDescriptor) {
        guard let value = event.paramDescriptor(forKeyword: keyDirectObject)?.stringValue,
              value.count <= 4096,
              value.lowercased().hasPrefix("oct://"),
              let binary = Bundle.main.object(forInfoDictionaryKey: "OctraClientBinary") as? String,
              let config = Bundle.main.object(forInfoDictionaryKey: "OctraClientConfig") as? String
        else { return }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = ["--config", config, "open-url", value]
        if let browser = Bundle.main.object(forInfoDictionaryKey: "OctraBrowserApp") as? String {
            var environment = ProcessInfo.processInfo.environment
            environment["OCTRAVPN_BROWSER_APP"] = browser
            process.environment = environment
        }
        do {
            try process.run()
        } catch {
            NSLog("Octra URL handler could not launch the client: %@", String(describing: error))
        }
    }
}

let app = NSApplication.shared
let handler = OctravpnUrlHandler()
app.delegate = handler
app.setActivationPolicy(.prohibited)
NSAppleEventManager.shared().setEventHandler(
    handler,
    andSelector: #selector(OctravpnUrlHandler.handleGetURL(_:withReplyEvent:)),
    forEventClass: AEEventClass(kInternetEventClass),
    andEventID: AEEventID(kAEGetURL)
)
app.run()
