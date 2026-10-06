// kcwatch: shows who is behind a KEYCHAIN password popup, right beside it.
//
// Twice a second it reads the on-screen window list (owners and positions only,
// so it needs no Screen Recording or Accessibility permission). The panel opens
// for genuine SecurityAgent/coreautha windows with an active securityd query.
// kcwho reads the OS-reported requester PID and the native query's lifetime.
// Helper account lookups never establish a dialog's requester.
// When a possible keychain prompt appears it runs `kcwho --json` in a small
// panel next to the popup. The panel never takes keyboard focus, so typing still
// goes to the popup. Read-only, like kcwho.
//
//     kcwatch [--kcwho PATH]      # watch (scripts/install.sh runs it at login)
//     kcwatch --snapshot PNG      # check once, draw the panel into PNG, quit

import AppKit
import Security

let usage = """
    usage: kcwatch [--kcwho PATH] [--snapshot PNG]
      --kcwho     kcwho to run (default: the copy next to this program)
      --snapshot  check once, draw the panel into PNG without showing it, quit
    """

// Genuine macOS keychain-password-prompt programs. A window from one of these,
// paired with a client, is a possible keychain prompt, not proof of attribution.
let appleOwners: Set<String> = ["SecurityAgent", "coreautha"]
let ownerExecutables = [
    "SecurityAgent": "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent",
    "coreautha": "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreautha.bundle/Contents/MacOS/coreautha"
]

struct Popup {
    let id: CGWindowID
    let owner: String
    let frame: CGRect  // window-list coordinates: origin at the main screen's top-left
}

// Same filter as kcwho: on screen, visible, big enough to be a dialog.
func popups() -> [Popup] {
    let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
    return list.compactMap { w in
        guard let owner = w[kCGWindowOwnerName as String] as? String, appleOwners.contains(owner),
              let pid = w[kCGWindowOwnerPID as String] as? pid_t,
              executablePath(pid) == ownerExecutables[owner],
              let id = w[kCGWindowNumber as String] as? CGWindowID,
              let alpha = w[kCGWindowAlpha as String] as? Double, alpha > 0,
              let bounds = w[kCGWindowBounds as String] as? NSDictionary,
              let frame = CGRect(dictionaryRepresentation: bounds as CFDictionary),
              frame.width >= 150, frame.height >= 80
        else { return nil }
        return Popup(id: id, owner: owner, frame: frame)
    }
}

func executablePath(_ pid: pid_t) -> String? {
    var path = [UInt8](repeating: 0, count: 4096)
    let n = Int(proc_pidpath(pid, &path, UInt32(path.count)))
    return n > 0 ? String(decoding: path.prefix(n), as: UTF8.self) : nil
}

// Metadata only: no task port, memory inspection, or Accessibility access.
func processInfo(_ pid: pid_t) -> [String: Any]? {
    var before = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, size) == size,
          let path = executablePath(pid) else { return nil }
    var result: [String: Any] = ["pid": pid, "path": path,
        "started": Double(before.pbi_start_tvsec) + Double(before.pbi_start_tvusec) / 1_000_000,
        "uid": before.pbi_uid, "signing": "Not checked"]
    var code: SecCode?
    let flags = SecCSFlags(rawValue: 0)
    let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
    if SecCodeCopyGuestWithAttributes(nil, attributes, flags, &code) == errSecSuccess, let code {
        var info: CFDictionary?
        var staticCode: SecStaticCode?
        if SecCodeCopyStaticCode(code, flags, &staticCode) == errSecSuccess, let staticCode,
           SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess, let info {
            let dictionary = info as NSDictionary
            result["identifier"] = dictionary[kSecCodeInfoIdentifier] as? String
            result["team"] = dictionary[kSecCodeInfoTeamIdentifier] as? String
            let signatureFlags = (dictionary[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
            var requirement: SecRequirement?
            let made = SecRequirementCreateWithString("anchor apple" as CFString, flags, &requirement)
            let apple = made == errSecSuccess && SecCodeCheckValidity(code, flags, requirement) == errSecSuccess
            result["apple_signed"] = apple
            result["signing"] = apple ? "Apple" : signatureFlags & 2 != 0 ? "Ad-hoc" :
                SecCodeCheckValidity(code, flags, nil) == errSecSuccess ? "Signed, not Apple" : "Not verified"
        }
    }
    var after = proc_bsdinfo()
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, size) == size,
          before.pbi_start_tvsec == after.pbi_start_tvsec,
          before.pbi_start_tvusec == after.pbi_start_tvusec,
          executablePath(pid) == path else { return nil }
    return result
}

// `kcwho --json`
struct Report: Decodable {
    struct Request: Decodable {
        let wants: String
        let job: String?
        let from: String?
        let chain: [String]
        let orphan: Bool
        let requester: String?
        let via: String?
        let evidence: String?
        let pid: Int?
        let tool: String?
        let signing: String?
        let originNote: String?
    }
    let name: String
    let waiting: [Request]
    let candidates: [Request]?
    let traceError: String?
    let kind: String?
}

enum Check {
    case checking
    case done(Report)
    case failed(String)
}

func runKcwho(_ path: String) -> Check {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = ["--json"]
    var env = ProcessInfo.processInfo.environment
    env["LANG"] = env["LANG"] ?? "en_US.UTF-8"  // launchd starts jobs without one
    p.environment = env
    let out = Pipe(), err = Pipe()
    p.standardOutput = out
    p.standardError = err
    do { try p.run() } catch { return .failed("can't run \(path): \(error.localizedDescription)") }
    let timeout = DispatchWorkItem { p.terminate() }
    DispatchQueue.global().asyncAfter(deadline: .now() + 15, execute: timeout)
    let json = out.fileHandleForReading.readDataToEndOfFile()
    let message = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    p.waitUntilExit()
    timeout.cancel()
    if p.terminationReason == .uncaughtSignal {
        return .failed(p.terminationStatus == SIGTERM ? "kcwho took over 15 s" : "kcwho crashed")
    }
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    if p.terminationStatus == 0, let report = try? decoder.decode(Report.self, from: json) {
        return .done(report)
    }
    return .failed(message.split(separator: "\n").last.map(String.init) ?? "kcwho exited \(p.terminationStatus)")
}

// One paragraph per add(), each with its own look.
final class Lines {
    private let text = NSMutableAttributedString()

    func add(_ s: String, font: NSFont = .systemFont(ofSize: 12), color: NSColor = .labelColor,
             gap: CGFloat = 0, indent: CGFloat = 0, truncate: Bool = false) {
        let style = NSMutableParagraphStyle()
        style.paragraphSpacingBefore = gap
        style.firstLineHeadIndent = indent
        style.headIndent = indent
        style.lineBreakMode = truncate ? .byTruncatingMiddle : .byWordWrapping
        let look: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color, .paragraphStyle: style]
        text.append(NSAttributedString(string: s + "\n", attributes: look))
    }

    var result: NSAttributedString {
        text.attributedSubstring(from: NSRange(location: 0, length: max(text.length - 1, 0)))
    }
}

// The panel's text and border color: blue = a requester named; orange = couldn't
// check, or couldn't name the requester. Never green: it says who is asking, not
// whether to say yes.
func content(_ check: Check) -> (NSAttributedString, NSColor) {
    let t = Lines()
    let bold = NSFont.boldSystemFont(ofSize: 12), small = NSFont.systemFont(ofSize: 11)
    t.add("Keychain requests reported by macOS", font: .boldSystemFont(ofSize: 13))
    let r: Report
    switch check {
    case .checking:
        t.add("Checking…", color: .secondaryLabelColor, gap: 4)
        return (t.result, .systemGray)
    case .failed(let why):
        t.add("⚠ Couldn't check: \(why)", font: bold, color: .systemOrange, gap: 4)
        t.add("Run kcwho in Terminal to see who's asking.")
        return (t.result, .systemOrange)
    case .done(let report):
        r = report
    }

    var unsure = false
    func feature(_ w: Report.Request) {
        let who = w.requester ?? "Requester not determined"
        if w.requester == nil { unsure = true }
        t.add(who, font: .boldSystemFont(ofSize: 17), color: .systemTeal, gap: 10)
        if let pid = w.pid { t.add("Direct requester · PID \(pid)", font: small, color: .secondaryLabelColor, gap: 2) }
        t.add("Request: \(w.wants)", gap: 2)
        if let path = w.tool { t.add(path, font: small, color: .secondaryLabelColor) }
        if let signing = w.signing { t.add("Current process signing: \(signing)", font: small, color: .secondaryLabelColor) }
        if let evidence = w.evidence {
            t.add(evidence, font: small, color: .secondaryLabelColor)
        }
        if let note = w.originNote { unsure = true; t.add(note, font: small, color: .systemOrange, gap: 4) }
    }

    if r.waiting.isEmpty {
        unsure = true
        t.add("Requester not determined", font: .boldSystemFont(ofSize: 17), color: .systemOrange, gap: 10)
        t.add("A running process alone does not establish who opened this dialog.", gap: 4)
        let names = Set((r.candidates ?? []).compactMap { $0.job ?? $0.from.map {
            String($0.split(separator: " ").first ?? Substring($0))
        } }).sorted()
        if !names.isEmpty {
            t.add("Running clients: " + names.joined(separator: ", "), font: small,
                  color: .secondaryLabelColor, gap: 6)
        }
    } else {
        r.waiting.forEach(feature)
        if r.waiting.count > 1 {
            unsure = true
            t.add("Several native Keychain requests are active. The owner of this individual dialog is not established.",
                  font: small, color: .systemOrange, gap: 8)
        }
    }
    if let why = r.traceError { t.add(why, font: small, color: .systemOrange, gap: 8) }
    t.add("Individual window association is not verified. If unsure, press Cancel.",
          font: small, color: .secondaryLabelColor, gap: 8)
    return (t.result, unsure ? .systemOrange : .systemBlue)
}

// One line for the log. Leaves out command lines: they can carry secrets.
func summary(_ check: Check) -> String {
    switch check {
    case .checking: return "checking"
    case .failed(let why): return "check failed: \(why)"
    case .done(let r):
        let callers = r.waiting.compactMap(\.requester)
        return callers.isEmpty ? "requester not determined" : "OS-reported requesters: " + callers.joined(separator: " | ")
    }
}

final class Card: NSView {
    var tint = NSColor.systemGray { didSet { needsDisplay = true } }

    override func draw(_ dirtyRect: NSRect) {
        let shape = NSBezierPath(roundedRect: bounds.insetBy(dx: 1.5, dy: 1.5), xRadius: 12, yRadius: 12)
        NSColor.windowBackgroundColor.setFill()
        shape.fill()
        tint.setStroke()
        shape.lineWidth = 3
        shape.stroke()
    }
}

final class HeadsUp: NSPanel {
    private let card = Card()
    private let label = NSTextField(wrappingLabelWithString: "")
    private let width: CGFloat = 440, inset: CGFloat = 16

    init() {
        super.init(contentRect: NSRect(x: 0, y: 0, width: width, height: 100),
                   styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        level = .statusBar  // below the popup's own level, so it can never cover the popup
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
        hidesOnDeactivate = false
        isOpaque = false
        backgroundColor = .clear
        hasShadow = true
        label.isSelectable = false
        card.addSubview(label)
        contentView = card
    }

    // Never key: keystrokes keep going to the password popup.
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }

    func update(_ look: (NSAttributedString, NSColor)) {
        label.attributedStringValue = look.0
        let inner = width - 2 * inset
        let fit = label.cell?.cellSize(forBounds: NSRect(x: 0, y: 0, width: inner, height: 10_000)) ?? .zero
        setContentSize(NSSize(width: width, height: ceil(fit.height) + 2 * inset))
        label.frame = NSRect(x: inset, y: inset, width: inner, height: ceil(fit.height))
        card.tint = look.1
        invalidateShadow()
    }

    // Beside the popup, on its screen: right, else left, below, above.
    func place(beside popup: CGRect) {
        guard let main = NSScreen.screens.first else { return }
        // Window-list y runs down from the main screen's top; AppKit's y runs up from its bottom.
        let box = NSRect(x: popup.minX, y: main.frame.maxY - popup.maxY, width: popup.width, height: popup.height)
        let area = (NSScreen.screens.first { $0.frame.intersects(box) } ?? main).visibleFrame
        let size = frame.size, gap: CGFloat = 12
        func onScreen(_ x: CGFloat, _ y: CGFloat) -> NSRect {
            NSRect(x: min(max(x, area.minX), area.maxX - size.width),
                   y: min(max(y, area.minY), area.maxY - size.height),
                   width: size.width, height: size.height)
        }
        let spots = [
            onScreen(box.maxX + gap, box.maxY - size.height),
            onScreen(box.minX - gap - size.width, box.maxY - size.height),
            onScreen(box.midX - size.width / 2, box.minY - gap - size.height),
            onScreen(box.midX - size.width / 2, box.maxY + gap),
        ]
        // No room anywhere: overlap. The popup still stays on top.
        let spot = spots.first { !$0.intersects(box) } ?? spots[0]
        if spot.origin != frame.origin { setFrameOrigin(spot.origin) }
    }

    func save(to path: String) throws {
        guard let view = contentView, let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        try bitmap.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
    }
}

let stamp: DateFormatter = {
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return f
}()

func log(_ line: String) {
    FileHandle.standardOutput.write(Data("\(stamp.string(from: Date())) \(line)\n".utf8))
}

final class Watch: NSObject, NSApplicationDelegate {
    let kcwho: String
    let panel = HeadsUp()
    var shownFor = ""         // window set the panel is currently shown for
    var round = 0             // bumped when the popup changes, so stale answers get dropped
    var busy = false          // a kcwho run is in flight
    var lastChecked = Date.distantPast
    var anchor: CGRect?       // the popup the panel sits beside
    var logged = ""
    // A windowless background app gets App Napped, which would stretch the 0.5 s poll.
    let awake = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
                                                      reason: "watching for keychain popups")

    init(kcwho: String) {
        self.kcwho = kcwho
    }

    func applicationDidFinishLaunching(_ note: Notification) {
        log("watching for password popups (kcwho: \(kcwho))")
        let timer = Timer(timeInterval: 0.5, target: self, selector: #selector(tick), userInfo: nil, repeats: true)
        timer.tolerance = 0.1
        RunLoop.main.add(timer, forMode: .common)
    }

    @objc func tick() {
        let found = popups()                      // SecurityAgent / coreautha windows
        let winIds = found.map { String($0.id) }.sorted().joined(separator: ",")
        let changed = winIds != shownFor
        if changed {
            shownFor = winIds
            round += 1; logged = ""
            panel.orderOut(nil)
        }
        guard let top = found.first else {
            anchor = nil
            return
        }
        anchor = top.frame
        // Query native prompt events for every genuine host, including unknown apps.
        guard !busy, changed || Date().timeIntervalSince(lastChecked) >= 2 else { return }
        lastChecked = Date()
        busy = true
        let (path, current) = (kcwho, round)
        DispatchQueue.global(qos: .userInitiated).async {
            let check = runKcwho(path)
            DispatchQueue.main.async { self.finish(check, round: current) }
        }
    }

    func finish(_ check: Check, round current: Int) {
        busy = false
        guard current == round, let anchor else { return }  // popups changed meanwhile: next tick re-checks
        if case .done(let report) = check, report.kind == "none" {
            panel.orderOut(nil)
            return
        }
        panel.update(content(check))
        panel.place(beside: anchor)
        panel.orderFrontRegardless()
        let line = summary(check)
        if line != logged {
            log(line)
            logged = line
        }
    }
}

func option(_ flag: String) -> String? {
    let args = CommandLine.arguments
    guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
    return args[i + 1]
}

if CommandLine.arguments.contains("-h") || CommandLine.arguments.contains("--help") {
    print(usage)
    exit(0)
}
let here = Bundle.main.executableURL?.deletingLastPathComponent() ?? URL(fileURLWithPath: ".")
let kcwho = option("--kcwho") ?? here.appendingPathComponent("kcwho").path
if let value = option("--process-info"), let pid = Int32(value) {
    guard let info = processInfo(pid), let data = try? JSONSerialization.data(withJSONObject: info) else { exit(1) }
    print(String(decoding: data, as: UTF8.self))
    exit(0)
}
let app = NSApplication.shared

if let png = option("--snapshot") {
    let panel = HeadsUp()
    let check = runKcwho(kcwho)
    panel.update(content(check))
    do {
        try panel.save(to: png)
    } catch {
        FileHandle.standardError.write(Data("can't write \(png): \(error.localizedDescription)\n".utf8))
        exit(1)
    }
    print(summary(check))
    exit(0)
}

app.setActivationPolicy(.accessory)
let watch = Watch(kcwho: kcwho)
app.delegate = watch
app.run()
