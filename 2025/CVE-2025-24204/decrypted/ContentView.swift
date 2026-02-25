//
//  ContentView.swift
//  decrypted
//
//  Created by Huy Nguyen on 4/9/25.
//

import SwiftUI
import Foundation
import UniformTypeIdentifiers

struct AppInfo: Identifiable {
    let id = UUID()
    let name: String
    let path: String
    let bundleId: String
    let isEncrypted: Bool
    let isRunning: Bool
    let fromAppStore: Bool
    let hasReceipt: Bool
    let location: String
    let version: String?
    let executablePath: String
    let binaryType: String
    let isIOS: Bool
    let buildNumber: String?
    let minimumSystemVersion: String?
    let frameworks: [String]
    
    init(name: String, path: String, bundleId: String, isEncrypted: Bool, isRunning: Bool, 
         fromAppStore: Bool, hasReceipt: Bool, location: String, version: String?, 
         executablePath: String, binaryType: String, isIOS: Bool, buildNumber: String?, 
         minimumSystemVersion: String?, frameworks: [String]) {
        self.name = name
        self.path = path
        self.bundleId = bundleId
        self.isEncrypted = isEncrypted
        self.isRunning = isRunning
        self.fromAppStore = fromAppStore
        self.hasReceipt = hasReceipt
        self.location = location
        self.version = version
        self.executablePath = executablePath
        self.binaryType = binaryType
        self.isIOS = isIOS
        self.buildNumber = buildNumber
        self.minimumSystemVersion = minimumSystemVersion
        self.frameworks = frameworks
    }
}

enum BinaryType: String, CaseIterable {
    case app = "app"
    case framework = "framework"
    case appex = "appex"
    case unknown = "unknown"
}

struct BinaryItem {
    let binaryType: BinaryType
    let executableURL: URL
    let bundleURL: URL
    let infoPlistURL: URL
}

class AppAnalyzer: ObservableObject {
    static let shared = AppAnalyzer()
    private init() {}
    
    func obtainBinaryLocations(searchPath: URL) -> [BinaryItem] {
        guard let enumerator = FileManager.default.enumerator(atPath: searchPath.path) else {
            return []
        }
        
        var binaryItems: [BinaryItem] = []
        
        for case let path as String in enumerator {
            let fullURL = searchPath.appendingPathComponent(path)
            
            if fullURL.lastPathComponent == "Info.plist" {
                if let binaryItem = convertToBinaryItem(infoPlistURL: fullURL) {
                    binaryItems.append(binaryItem)
                }
            }
        }
        
        return binaryItems
    }
    
    private func convertToBinaryItem(infoPlistURL: URL) -> BinaryItem? {
        do {
            let data = try Data(contentsOf: infoPlistURL)
            guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
                return nil
            }
            
            guard let executableName = plist["CFBundleExecutable"] as? String else {
                return nil
            }
            
            let bundleURL = infoPlistURL.deletingLastPathComponent()
            let executableURL = bundleURL.appendingPathComponent(executableName)
            
            var isDirectory: ObjCBool = false
            let exists = FileManager.default.fileExists(atPath: executableURL.path, isDirectory: &isDirectory)
            
            if isDirectory.boolValue || !exists {
                return nil
            }
            
            let bundleName = bundleURL.lastPathComponent
            let binaryType: BinaryType
            
            if bundleName.hasSuffix(".appex") {
                binaryType = .appex
            } else if bundleName.hasSuffix(".framework") {
                binaryType = .framework
            } else if bundleName.hasSuffix(".app") {
                binaryType = .app
            } else {
                binaryType = .unknown
            }
            
            return BinaryItem(
                binaryType: binaryType,
                executableURL: executableURL,
                bundleURL: bundleURL,
                infoPlistURL: infoPlistURL
            )
            
        } catch {
            return nil
        }
    }
    
    func scanApplications() -> [AppInfo] {
        let searchPaths = [
            URL(fileURLWithPath: "/Applications"),
        ]
        
        var apps: [AppInfo] = []
        var scannedPaths = Set<String>()
        
        for searchPath in searchPaths {
            guard FileManager.default.fileExists(atPath: searchPath.path) else { continue }
            
            let binaryItems = obtainBinaryLocations(searchPath: searchPath)
            
            for binaryItem in binaryItems {
                guard binaryItem.binaryType == .app else { continue }
                
                let bundlePath = binaryItem.bundleURL.path
                if scannedPaths.contains(bundlePath) { continue }
                scannedPaths.insert(bundlePath)
                
                if let appInfo = analyzeApp(binaryItem: binaryItem, location: searchPath.path) {
                    apps.append(appInfo)
                }
            }
        }
        
        // Sort by iOS apps first, then App Store apps, then by name
        apps.sort { lhs, rhs in
            if lhs.isIOS != rhs.isIOS {
                return lhs.isIOS && !rhs.isIOS
            }
            if lhs.fromAppStore != rhs.fromAppStore {
                return lhs.fromAppStore && !rhs.fromAppStore
            }
            return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
        }
        
        return apps
    }
    
    private func analyzeApp(binaryItem: BinaryItem, location: String) -> AppInfo? {
        do {
            let data = try Data(contentsOf: binaryItem.infoPlistURL)
            guard let bundleInfo = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
                return nil
            }
            
            let appName = (bundleInfo["CFBundleDisplayName"] as? String) ?? 
                         (bundleInfo["CFBundleName"] as? String) ?? 
                         binaryItem.bundleURL.lastPathComponent.replacingOccurrences(of: ".app", with: "")
            
            let bundleId = bundleInfo["CFBundleIdentifier"] as? String ?? "unknown"
            let version = bundleInfo["CFBundleShortVersionString"] as? String
            let buildNumber = bundleInfo["CFBundleVersion"] as? String
            let minimumSystemVersion = bundleInfo["LSMinimumSystemVersion"] as? String
            
            // Check if it's an iOS app
            let isIOS = isIOSApp(bundlePath: binaryItem.bundleURL.path)
            
            // Check if it's encrypted (for iOS apps)
            let isEncrypted = isIOS ? isAppEncrypted(executablePath: binaryItem.executableURL.path) : false
            
            // Check if app is running
            let isRunning = isProcessRunning(appName: appName)
            
            // Check App Store info
            let (fromAppStore, hasReceipt) = getAppStoreInfo(bundlePath: binaryItem.bundleURL.path)
            
            // Find frameworks
            let frameworks = findFrameworks(bundlePath: binaryItem.bundleURL.path)
            
            return AppInfo(
                name: appName,
                path: binaryItem.bundleURL.path,
                bundleId: bundleId,
                isEncrypted: isEncrypted,
                isRunning: isRunning,
                fromAppStore: fromAppStore,
                hasReceipt: hasReceipt,
                location: location,
                version: version,
                executablePath: binaryItem.executableURL.path,
                binaryType: binaryItem.binaryType.rawValue,
                isIOS: isIOS,
                buildNumber: buildNumber,
                minimumSystemVersion: minimumSystemVersion,
                frameworks: frameworks
            )
            
        } catch {
            return nil
        }
    }
    
    private func isIOSApp(bundlePath: String) -> Bool {
        // Check if this app has a Wrapper directory
        let wrapperPath = bundlePath + "/Wrapper"
        if FileManager.default.fileExists(atPath: wrapperPath) {
            return true
        }
        
        // Check if this app is inside a Wrapper directory
        if bundlePath.contains("Wrapper") {
            return true
        }
        
        // Check parent directories for Wrapper
        var parentPath = (bundlePath as NSString).deletingLastPathComponent
        while !parentPath.isEmpty && parentPath != "/" {
            if (parentPath as NSString).lastPathComponent == "Wrapper" {
                return true
            }
            parentPath = (parentPath as NSString).deletingLastPathComponent
        }
        
        return false
    }
    
    private func isAppEncrypted(executablePath: String) -> Bool {
        return true
    }
    
    private func isProcessRunning(appName: String) -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        task.arguments = ["-x", appName]
        
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }
    
    private func getAppStoreInfo(bundlePath: String) -> (fromAppStore: Bool, hasReceipt: Bool) {
        let receiptPath = bundlePath + "/Contents/_MASReceipt/receipt"
        let hasReceipt = FileManager.default.fileExists(atPath: receiptPath)
        
        let fromAppStore = hasReceipt
        
        return (fromAppStore, hasReceipt)
    }
    
    private func findFrameworks(bundlePath: String) -> [String] {
        var frameworks: [String] = []
        
        let frameworksPath = bundlePath + "/Contents/Frameworks"
        
        do {
            let contents = try FileManager.default.contentsOfDirectory(atPath: frameworksPath)
            for item in contents {
                if item.hasSuffix(".framework") {
                    frameworks.append(item)
                }
            }
        } catch {
            //
        }
        
        return frameworks
    }
}

struct DecryptionTask: Identifiable {
    let id = UUID()
    let appInfo: AppInfo
    var status: DecryptionStatus
    var progress: Double
    var message: String
}

enum DecryptionStatus {
    case pending
    case running
    case completed
    case failed
}

class AppDecryptionManager: ObservableObject {
    @Published var availableApps: [AppInfo] = []
    @Published var decryptionTasks: [DecryptionTask] = []
    @Published var isScanning = false
    @Published var scanningMessage = ""
    @Published var signingIdentity = ""
    @Published var profilePath = ""
    @Published var entitlementsPath = ""
    @Published var isSettingUpEnvironment = false
    @Published var environmentSetupMessage = ""
    
    private let decryptScriptPath = Bundle.main.path(forResource: "decrypt_fairplay", ofType: "py") ?? 
                                   (Bundle.main.resourcePath ?? "") + "/decrypt_fairplay.py"
    private let requirementsPath = Bundle.main.path(forResource: "requirements", ofType: "txt") ?? 
                                  (Bundle.main.resourcePath ?? "") + "/requirements.txt"
    
    // Virtual environment paths
    private var venvPath: String {
        // Use app's Application Support directory within sandbox
        let appSupportURL = FileManager.default.urls(for: .applicationSupportDirectory, 
                                                    in: .userDomainMask).first!
        let appSupportPath = appSupportURL.appendingPathComponent("com.34306.decrypted").path
        
        // Create directory if it doesn't exist
        try? FileManager.default.createDirectory(atPath: appSupportPath, 
                                                withIntermediateDirectories: true, 
                                                attributes: nil)
        
        return "\(appSupportPath)/python_venv"
    }
    
    private var venvPythonPath: String {
        return "\(venvPath)/bin/python3"
    }
    
    private var venvPipPath: String {
        return "\(venvPath)/bin/pip3"
    }
    
    func scanForApps() {
        isScanning = true
        scanningMessage = "Scanning for applications..."
        
        DispatchQueue.global(qos: .background).async {
            let analyzer = AppAnalyzer.shared
            let apps = analyzer.scanApplications()
            
            DispatchQueue.main.async {
                self.availableApps = apps
                let iosApps = apps.filter { $0.isIOS }
                let encryptedApps = iosApps.filter { $0.isEncrypted }
                
                if iosApps.isEmpty {
                    self.scanningMessage = "No iOS apps found"
                } else {
                    self.scanningMessage = "Found \(iosApps.count) iOS apps (\(encryptedApps.count) encrypted)"
                }
                
                self.isScanning = false
            }
        }
    }
    
    // MARK: - Virtual Environment Management
    
    func setupVirtualEnvironment() async {
        await MainActor.run {
            isSettingUpEnvironment = true
            environmentSetupMessage = "Setting up Python environment..."
        }
        
        do {
            // Log the virtual environment path for debugging
            print("Virtual environment path: \(venvPath)")
            
            // Check if virtual environment already exists
            if FileManager.default.fileExists(atPath: venvPath) {
                await MainActor.run {
                    environmentSetupMessage = "Virtual environment exists, updating dependencies..."
                }
            } else {
                // Create virtual environment
                await MainActor.run {
                    environmentSetupMessage = "Creating virtual environment in sandbox..."
                }
                try await createVirtualEnvironment()
            }
            
            // Install/update requirements
            await MainActor.run {
                environmentSetupMessage = "Installing Python dependencies..."
            }
            try await installRequirements()
            
            await MainActor.run {
                isSettingUpEnvironment = false
                environmentSetupMessage = "Environment ready! Located in app sandbox."
            }
            
            // Auto-clear the message after 3 seconds
            Task { @MainActor in
                try await Task.sleep(nanoseconds: 3_000_000_000)
                self.environmentSetupMessage = ""
            }
            
        } catch {
            await MainActor.run {
                isSettingUpEnvironment = false
                environmentSetupMessage = "Setup failed: \(error.localizedDescription)"
            }
            
            // Log detailed error information
            print("Virtual environment setup error: \(error)")
            if let nsError = error as NSError? {
                print("Error domain: \(nsError.domain), code: \(nsError.code)")
                print("Error info: \(nsError.userInfo)")
            }
        }
    }
    
    private func createVirtualEnvironment() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-m", "venv", venvPath]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        try process.run()
        process.waitUntilExit()
        
        guard process.terminationStatus == 0 else {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw NSError(domain: "VenvCreation", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: output])
        }
    }
    
    private func installRequirements() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: venvPipPath)
        process.arguments = ["install", "-r", requirementsPath]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        try process.run()
        process.waitUntilExit()
        
        guard process.terminationStatus == 0 else {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw NSError(domain: "RequirementsInstall", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: output])
        }
    }
    
    func checkVirtualEnvironment() -> Bool {
        return FileManager.default.fileExists(atPath: venvPythonPath)
    }
    
    func cleanupVirtualEnvironment() {
        do {
            if FileManager.default.fileExists(atPath: venvPath) {
                try FileManager.default.removeItem(atPath: venvPath)
                environmentSetupMessage = "Virtual environment cleaned up from sandbox"
                
                Task { @MainActor in
                    try await Task.sleep(nanoseconds: 3_000_000_000)
                    self.environmentSetupMessage = ""
                }
            } else {
                environmentSetupMessage = "No virtual environment found to cleanup"
                
                // Auto-clear the message after 2 seconds
                Task { @MainActor in
                    try await Task.sleep(nanoseconds: 2_000_000_000)
                    self.environmentSetupMessage = ""
                }
            }
        } catch {
            environmentSetupMessage = "Failed to cleanup: \(error.localizedDescription)"
            print("Cleanup error: \(error)")
        }
    }
    
    func decryptApp(_ app: AppInfo) {
        // Check if virtual environment exists, set it up if not
        if !checkVirtualEnvironment() {
            Task {
                await setupVirtualEnvironment()
                // After setup, proceed with decryption
                await MainActor.run {
                    self.performDecryption(for: app)
                }
            }
            return
        }
        
        performDecryption(for: app)
    }
    
    private func performDecryption(for app: AppInfo) {
        let task = DecryptionTask(
            appInfo: app,
            status: .pending,
            progress: 0.0,
            message: "Preparing decryption..."
        )
        
        DispatchQueue.main.async {
            self.decryptionTasks.append(task)
        }
        
        DispatchQueue.global(qos: .background).async {
            self.performDecryption(task)
        }
    }
    
    private func performDecryption(_ task: DecryptionTask) {
        guard let taskIndex = decryptionTasks.firstIndex(where: { $0.id == task.id }) else { return }
        
        DispatchQueue.main.async {
            self.decryptionTasks[taskIndex].status = .running
            self.decryptionTasks[taskIndex].message = "Starting decryption process..."
        }
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        process.arguments = [
            venvPythonPath,  // Use virtual environment Python
            decryptScriptPath,
            task.appInfo.name,
            "-s", signingIdentity,
            "-p", profilePath,
            "-e", entitlementsPath
        ]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
            
            // Monitor progress
            let fileHandle = pipe.fileHandleForReading
            fileHandle.readabilityHandler = { handle in
                let data = handle.availableData
                if let output = String(data: data, encoding: .utf8), !output.isEmpty {
                    DispatchQueue.main.async {
                        if let taskIndex = self.decryptionTasks.firstIndex(where: { $0.id == task.id }) {
                            let lines = output.components(separatedBy: .newlines)
                            for line in lines {
                                if line.contains("[PROGRESS:") {
                                    let regex = try! NSRegularExpression(pattern: "\\[PROGRESS:(\\d+\\.\\d+)\\] (.+)")
                                    if let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) {
                                        if let progressRange = Range(match.range(at: 1), in: line),
                                           let messageRange = Range(match.range(at: 2), in: line) {
                                            let progressValue = Double(String(line[progressRange])) ?? 0.0
                                            let message = String(line[messageRange])
                                            
                                            self.decryptionTasks[taskIndex].progress = progressValue / 100.0
                                            self.decryptionTasks[taskIndex].message = message
                                        }
                                    }
                                } else if !line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                    self.decryptionTasks[taskIndex].message = line.trimmingCharacters(in: .whitespacesAndNewlines)
                                }
                            }
                        }
                    }
                }
            }
            
            process.waitUntilExit()
            
            DispatchQueue.main.async {
                if let taskIndex = self.decryptionTasks.firstIndex(where: { $0.id == task.id }) {
                    if process.terminationStatus == 0 {
                        self.decryptionTasks[taskIndex].status = .completed
                        self.decryptionTasks[taskIndex].progress = 1.0
                        self.decryptionTasks[taskIndex].message = "Decryption completed successfully!"
                    } else {
                        self.decryptionTasks[taskIndex].status = .failed
                        self.decryptionTasks[taskIndex].message = "Decryption failed with exit code \(process.terminationStatus)"
                    }
                }
            }
            
        } catch {
            DispatchQueue.main.async {
                if let taskIndex = self.decryptionTasks.firstIndex(where: { $0.id == task.id }) {
                    self.decryptionTasks[taskIndex].status = .failed
                    self.decryptionTasks[taskIndex].message = "Error: \(error.localizedDescription)"
                }
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var manager = AppDecryptionManager()
    @State private var selectedTab = 0
    @State private var showingSettings = false
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 32))
                    .foregroundColor(.blue)
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("FairPlay Decryptor")
                        .font(.title)
                        .fontWeight(.bold)
                    Text("iPA Decryption Tool using [CVE-2025-24204](https://github.com/FFRI/CVE-2025-24204) by Koh M. Nakagawa (@tsunek0h) from [FFRI](https://github.com/FFRI)\nApp by [34306](https://github.com/34306)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Button(action: { showingSettings = true }) {
                    Image(systemName: "gear")
                        .font(.title2)
                        .foregroundColor(.primary)
                }
                .buttonStyle(.plain)
                .help("Settings")
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            // Content
            TabView(selection: $selectedTab) {
                AppScannerView(manager: manager)
                    .tabItem {
                        Image(systemName: "magnifyingglass")
                        Text("Scanner")
                    }
                    .tag(0)
                
                DecryptionTasksView(manager: manager)
                    .tabItem {
                        Image(systemName: "lock.open")
                        Text("Decryption")
                    }
                    .tag(1)
            }
        }
        .sheet(isPresented: $showingSettings) {
            SettingsView(manager: manager)
        }
        .frame(minWidth: 900, minHeight: 650)
        .background(Color(NSColor.windowBackgroundColor))
    }
}

struct AppScannerView: View {
    @ObservedObject var manager: AppDecryptionManager
    
    var body: some View {
        VStack(spacing: 0) {
            // Scan Controls
            HStack(spacing: 16) {
                Button(action: manager.scanForApps) {
                    HStack(spacing: 8) {
                        Image(systemName: manager.isScanning ? "arrow.clockwise" : "magnifyingglass")
                            .rotationEffect(.degrees(manager.isScanning ? 360 : 0))
                            .animation(manager.isScanning ? .linear(duration: 1).repeatForever(autoreverses: false) : .default, value: manager.isScanning)
                        Text(manager.isScanning ? "Scanning..." : "Scan for Apps")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(manager.isScanning)
                
                if manager.isScanning {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .blue))
                        .scaleEffect(0.8)
                }
                
                if !manager.scanningMessage.isEmpty {
                    Text(manager.scanningMessage)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
                
                Spacer()
                
                if !manager.availableApps.isEmpty {
                    Text("\(manager.availableApps.count) apps found")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(Color.blue.opacity(0.1))
                        .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            // Apps List
            if manager.availableApps.isEmpty && !manager.isScanning {
                VStack(spacing: 16) {
                    Image(systemName: "magnifyingglass.circle")
                        .font(.system(size: 64))
                        .foregroundColor(.secondary)
                    
                    Text("No Applications Found")
                        .font(.title2)
                        .fontWeight(.semibold)
                        .foregroundColor(.secondary)
                    
                    Text("Click 'Scan for Apps' to find applications on your system")
                        .font(.body)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 40)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(manager.availableApps) { app in
                    AppRowView(app: app, onDecrypt: { manager.decryptApp(app) })
                        .padding(.vertical, 4)
                }
                .listStyle(.inset)
            }
        }
    }
}

struct AppRowView: View {
    let app: AppInfo
    let onDecrypt: () -> Void
    
    var body: some View {
        HStack(spacing: 16) {
            // App Icon Placeholder
            RoundedRectangle(cornerRadius: 12)
                .fill(LinearGradient(
                    gradient: Gradient(colors: [Color.blue.opacity(0.2), Color.blue.opacity(0.1)]),
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ))
                .frame(width: 50, height: 50)
                .overlay(
                    Image(systemName: "app")
                        .font(.title2)
                        .foregroundColor(.blue)
                )
            
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(app.name)
                        .font(.headline)
                        .lineLimit(1)
                    
                    if let version = app.version {
                        Text("v\(version)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.secondary.opacity(0.1))
                            .clipShape(Capsule())
                    }
                    
                    if let buildNumber = app.buildNumber {
                        Text("(\(buildNumber))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()
                }
                
                Text(app.bundleId)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                
                // First row of badges
                HStack(spacing: 8) {
                    if app.isIOS == true {
                        Label("iOS App", systemImage: "iphone")
                            .font(.caption)
                            .foregroundColor(.purple)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(Color.purple.opacity(0.1))
                            .clipShape(Capsule())
                    }
                    
                    Label(app.isEncrypted ? "Encrypted" : "Not Encrypted", 
                          systemImage: app.isEncrypted ? "lock.fill" : "lock.open")
                        .font(.caption)
                        .foregroundColor(app.isEncrypted ? .orange : .green)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(app.isEncrypted ? Color.orange.opacity(0.1) : Color.green.opacity(0.1))
                        .clipShape(Capsule())
                    
                    if app.fromAppStore == true {
                        Label("App Store", systemImage: "bag")
                            .font(.caption)
                            .foregroundColor(.blue)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(Color.blue.opacity(0.1))
                            .clipShape(Capsule())
                    }
                    
                    if app.isRunning {
                        Label("Running", systemImage: "circle.fill")
                            .font(.caption)
                            .foregroundColor(.green)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(Color.green.opacity(0.1))
                            .clipShape(Capsule())
                    }
                }
                
                // Second row for additional info
                if !app.frameworks.isEmpty {
                    HStack(spacing: 4) {
                        Label("\(app.frameworks.count) frameworks", systemImage: "square.stack.3d.up")
                            .font(.caption)
                            .foregroundColor(.indigo)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.indigo.opacity(0.1))
                            .clipShape(Capsule())
                        
                        Text(app.frameworks.prefix(3).joined(separator: ", "))
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }
                
                // Additional info for different app types
                if !app.isIOS && !app.frameworks.isEmpty {
                    Text("macOS app with \(app.frameworks.count) frameworks")
                        .font(.caption)
                        .foregroundColor(.orange)
                        .lineLimit(1)
                }
                
                if app.location != "/Applications" {
                    Text("Location: \(app.location)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
                
                if let minVersion = app.minimumSystemVersion {
                    Text("Requires macOS \(minVersion)+")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }
            
            Spacer()
            
            if app.isIOS && app.isEncrypted {
                Button(action: onDecrypt) {
                    HStack(spacing: 6) {
                        Image(systemName: "key")
                        Text("Decrypt")
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
            } else if app.isIOS && !app.isEncrypted {
                Text("Not Encrypted")
                    .font(.caption)
                    .foregroundColor(.green)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.green.opacity(0.1))
                    .clipShape(Capsule())
            } else {
                Text("macOS App")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.secondary.opacity(0.1))
                    .clipShape(Capsule())
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct DecryptionTasksView: View {
    @ObservedObject var manager: AppDecryptionManager
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 16) {
                Text("Decryption Tasks")
                    .font(.title2)
                    .fontWeight(.semibold)
                
                Spacer()
                
                if !manager.decryptionTasks.filter({ $0.status == .completed }).isEmpty {
                    Button(action: {
                        manager.decryptionTasks.removeAll { $0.status == .completed }
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "trash")
                            Text("Clear Completed")
                        }
                    }
                    .buttonStyle(.bordered)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            if manager.decryptionTasks.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "tray.circle")
                        .font(.system(size: 64))
                        .foregroundColor(.secondary)
                    
                    Text("No Decryption Tasks")
                        .font(.title2)
                        .fontWeight(.semibold)
                        .foregroundColor(.secondary)
                    
                    Text("Select an encrypted app from the Scanner tab to begin decryption")
                        .font(.body)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 40)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(manager.decryptionTasks) { task in
                    DecryptionTaskRowView(task: task)
                        .padding(.vertical, 4)
                }
                .listStyle(.inset)
            }
        }
    }
}

struct DecryptionTaskRowView: View {
    let task: DecryptionTask
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(task.appInfo.name)
                        .font(.headline)
                        .lineLimit(1)
                    
                    Text(task.appInfo.bundleId)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
                
                Spacer()
                
                StatusBadge(status: task.status)
            }
            
            if task.status == .running {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("Progress: \(Int(task.progress * 100))%")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        
                        Spacer()
                        
                        Text("\(Int(task.progress * 100))%")
                            .font(.caption)
                            .fontWeight(.medium)
                            .foregroundColor(.blue)
                    }
                    
                    ProgressView(value: task.progress)
                        .progressViewStyle(LinearProgressViewStyle(tint: .blue))
                }
            }
            
            if !task.message.isEmpty {
                Text(task.message)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .lineLimit(3)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Color(NSColor.textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct StatusBadge: View {
    let status: DecryptionStatus
    
    var body: some View {
        let (text, color, icon) = statusInfo
        
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.caption)
            Text(text)
                .font(.caption)
                .fontWeight(.medium)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(color.opacity(0.15))
        .foregroundColor(color)
        .clipShape(Capsule())
        .overlay(
            Capsule()
                .stroke(color.opacity(0.3), lineWidth: 1)
        )
    }
    
    private var statusInfo: (String, Color, String) {
        switch status {
        case .pending:
            return ("Pending", .orange, "clock")
        case .running:
            return ("Running", .blue, "gear")
        case .completed:
            return ("Completed", .green, "checkmark.circle")
        case .failed:
            return ("Failed", .red, "xmark.circle")
        }
    }
}

struct SettingsView: View {
    @ObservedObject var manager: AppDecryptionManager
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Settings")
                    .font(.title2)
                    .fontWeight(.semibold)
                
                Spacer()
                
                HStack(spacing: 12) {
                    Button("Cancel") {
                        presentationMode.wrappedValue.dismiss()
                    }
                    .buttonStyle(.bordered)
                    
                    Button("Done") {
                        presentationMode.wrappedValue.dismiss()
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 20)
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            ScrollView {
                VStack(spacing: 32) {
                    // Virtual Environment Section
                    VStack(alignment: .leading, spacing: 20) {
                        HStack {
                            Image(systemName: "gear.badge.checkmark")
                                .font(.title2)
                                .foregroundColor(.green)
                            
                            Text("Python Environment")
                                .font(.title3)
                                .fontWeight(.semibold)
                        }
                        
                        VStack(spacing: 16) {
                            HStack {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text("Virtual Environment Status")
                                        .font(.subheadline)
                                        .fontWeight(.medium)
                                        .foregroundColor(.primary)
                                    
                                    VirtualEnvironmentStatusText(manager: manager)
                                }
                                
                                Spacer()
                                
                                HStack(spacing: 12) {
                                    VirtualEnvironmentSetupButton(manager: manager)
                                    
                                    if manager.checkVirtualEnvironment() {
                                        Button("Reset") {
                                            manager.cleanupVirtualEnvironment()
                                        }
                                        .buttonStyle(.bordered)
                                        .help("Remove virtual environment to force clean setup")
                                    }
                                }
                            }
                            
                            if !manager.environmentSetupMessage.isEmpty {
                                HStack {
                                    Image(systemName: manager.environmentSetupMessage.contains("failed") ? "exclamationmark.triangle" : "info.circle")
                                        .foregroundColor(manager.environmentSetupMessage.contains("failed") ? .red : .blue)
                                    
                                    Text(manager.environmentSetupMessage)
                                        .font(.caption)
                                        .foregroundColor(manager.environmentSetupMessage.contains("failed") ? .red : .secondary)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(manager.environmentSetupMessage.contains("failed") ? Color.red.opacity(0.1) : Color.blue.opacity(0.1))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            }
                        }
                    }
                    .padding(20)
                    .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    
                    // Code Signing Section
                    VStack(alignment: .leading, spacing: 20) {
                        HStack {
                            Image(systemName: "signature")
                                .font(.title2)
                                .foregroundColor(.blue)
                            
                            Text("Code Signing Configuration")
                                .font(.title3)
                                .fontWeight(.semibold)
                        }
                        
                        VStack(spacing: 16) {
                            // Signing Identity
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Signing Identity")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                    .foregroundColor(.primary)
                                
                                Text("Your Apple Developer certificate name")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                
                                TextField("Apple Development: Your Name (XXXXXXXXXX)", text: $manager.signingIdentity)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(.body, design: .monospaced))
                            }
                            
                            // Provisioning Profile
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Provisioning Profile")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                    .foregroundColor(.primary)
                                
                                Text("Path to your .mobileprovision file")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                
                                HStack(spacing: 8) {
                                    TextField("/path/to/profile.mobileprovision", text: $manager.profilePath)
                                        .textFieldStyle(.roundedBorder)
                                        .font(.system(.body, design: .monospaced))
                                    
                                    Button(action: {
                                        selectFile(for: \.profilePath, fileTypes: ["mobileprovision"])
                                    }) {
                                        HStack(spacing: 4) {
                                            Image(systemName: "folder")
                                            Text("Browse")
                                        }
                                    }
                                    .buttonStyle(.bordered)
                                }
                            }
                            
                            // Entitlements File
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Entitlements File")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                    .foregroundColor(.primary)
                                
                                Text("Path to your entitlements XML file")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                
                                HStack(spacing: 8) {
                                    TextField("/path/to/entitlements.xml", text: $manager.entitlementsPath)
                                        .textFieldStyle(.roundedBorder)
                                        .font(.system(.body, design: .monospaced))
                                    
                                    Button(action: {
                                        selectFile(for: \.entitlementsPath, fileTypes: ["xml", "plist"])
                                    }) {
                                        HStack(spacing: 4) {
                                            Image(systemName: "folder")
                                            Text("Browse")
                                        }
                                    }
                                    .buttonStyle(.bordered)
                                }
                            }
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.vertical, 20)
                    .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    
                    // Information Section
                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            Image(systemName: "info.circle")
                                .font(.title2)
                                .foregroundColor(.blue)
                            
                            Text("About CVE-2025-24204")
                                .font(.title3)
                                .fontWeight(.semibold)
                        }
                        
                        Text("This tool exploits CVE-2025-24204, a vulnerability that allows reading any process memory on SIP-enabled macOS systems. It enables decryption of FairPlay-encrypted iOS apps running on Apple Silicon Macs.")
                            .font(.body)
                            .foregroundColor(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Requirements:")
                                .font(.subheadline)
                                .fontWeight(.semibold)
                            
                            VStack(alignment: .leading, spacing: 8) {
                                RequirementRow(icon: "desktopcomputer", title: "macOS 15.0-15.2 (Sequoia)", description: "Required for CVE-2025-24204 vulnerability")
                                RequirementRow(icon: "person.badge.key", title: "Apple Developer Program", description: "Valid membership for code signing")
                                RequirementRow(icon: "signature", title: "Signing Credentials", description: "Certificate and provisioning profile")
                                RequirementRow(icon: "lock.shield", title: "Administrator Privileges", description: "Required for memory dumping operations")
                            }
                        }
                        
                        // Quick Setup Help
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Quick Setup:")
                                .font(.subheadline)
                                .fontWeight(.semibold)
                            
                            Text("1. Run 'security find-identity -v -p codesigning' to find your signing identity")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            
                            Text("2. Create an entitlements.xml file with your app's bundle identifier")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            
                            Text("3. Download a development provisioning profile from Apple Developer portal")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.vertical, 20)
                    .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .padding(24)
            }
        }
        .frame(minWidth: 700, minHeight: 600)
        .background(Color(NSColor.windowBackgroundColor))
    }
    
    private func selectFile(for keyPath: ReferenceWritableKeyPath<AppDecryptionManager, String>, fileTypes: [String] = []) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        
        if !fileTypes.isEmpty {
            panel.allowedContentTypes = fileTypes.compactMap { ext in
                UTType(filenameExtension: ext)
            }
        }
        
        if panel.runModal() == .OK {
            if let url = panel.url {
                manager[keyPath: keyPath] = url.path
            }
        }
    }
}

struct RequirementRow: View {
    let icon: String
    let title: String
    let description: String
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundColor(.blue)
                .frame(width: 24)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.medium)
                
                Text(description)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.3))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct VirtualEnvironmentStatusText: View {
    @ObservedObject var manager: AppDecryptionManager
    
    var body: some View {
        let isReady = manager.checkVirtualEnvironment()
        Text(isReady ? 
             "✅ Ready - Isolated Python environment with required dependencies" : 
             "❌ Not Set Up - Virtual environment needs to be created")
            .font(.caption)
            .foregroundColor(isReady ? .green : .secondary)
    }
}

struct VirtualEnvironmentSetupButton: View {
    @ObservedObject var manager: AppDecryptionManager
    
    var body: some View {
        Button(action: {
            Task {
                await manager.setupVirtualEnvironment()
            }
        }) {
            HStack(spacing: 6) {
                if manager.isSettingUpEnvironment {
                    ProgressView()
                        .scaleEffect(0.7)
                } else {
                    let isReady = manager.checkVirtualEnvironment()
                    Image(systemName: isReady ? "arrow.clockwise" : "plus.circle")
                }
                
                let isReady = manager.checkVirtualEnvironment()
                Text(isReady ? "Update" : "Setup")
            }
        }
        .buttonStyle(.borderedProminent)
        .disabled(manager.isSettingUpEnvironment)
    }
}

#Preview {
    ContentView()
}
