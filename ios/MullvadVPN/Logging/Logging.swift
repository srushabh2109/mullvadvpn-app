//
//  Logging.swift
//  MullvadVPN
//
//  Created by pronebird on 02/08/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging

func initLoggingSystem(bundleIdentifier: String) {
    let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: ApplicationConfiguration.securityGroupIdentifier)!
    let logsDirectoryURL = containerURL.appendingPathComponent("Logs", isDirectory: true)
    let logFileName = "\(bundleIdentifier).log"
    let logFileURL = logsDirectoryURL.appendingPathComponent(logFileName)

    // Create Logs folder within container if it doesn't exist
    try? FileManager.default.createDirectory(at: logsDirectoryURL, withIntermediateDirectories: false, attributes: nil)

    // Rotate log
    let logRotationResult = LogRotation.rotateLog(logsDirectory: logsDirectoryURL, logFileName: logFileName)

    // Create an array of log output streams
    var streams: [TextOutputStream] = []

    #if DEBUG
    // Add standard output logging in debug
    streams.append(TextFileOutputStream.standardOutputStream())
    #endif

    // Create output stream to file
    if let fileLogStream = TextFileOutputStream(fileURL: logFileURL, createFile: true) {
        streams.append(fileLogStream)
    }

    // Configure Logging system
    LoggingSystem.bootstrap { (label) -> LogHandler in
        if streams.isEmpty {
            return SwiftLogNoOpLogHandler()
        } else {
            return CustomFormatLogHandler(label: label, streams: streams)
        }
    }

    if case .failure(let logRotationError) = logRotationResult {
        Logger(label: "LogRotation")
            .error(chainedError: logRotationError, message: "Failed to rotate log")
    }
}
