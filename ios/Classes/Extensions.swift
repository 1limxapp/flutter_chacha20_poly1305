//
//  Extensions.swift
//  flutter_chacha20_poly1305
//
//  Created by Macbook Pro on 16/08/2023.
//

import Foundation

public extension Data {
    private static let regex = try! NSRegularExpression(pattern: "([0-9a-fA-F]{2})", options: [])
    init?(hexString: String) {
        guard hexString.count.isMultiple(of: 2) else {
            return nil
        }
        
        let chars = hexString.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }
        
        guard hexString.count / bytes.count == 2 else { return nil }
        self.init(bytes)
    }

    /// Hexadecimal string representation of `Data` object.
    var hexadecimal: String {
        let charA: UInt8 = 0x61
        let char0: UInt8 = 0x30
        func byteToChar(_ b: UInt8) -> Character {
            Character(UnicodeScalar(b > 9 ? charA + b - 10 : char0 + b))
        }
        let hexChars = flatMap {[
            byteToChar(($0 >> 4) & 0xF),
            byteToChar($0 & 0xF)
        ]}
        return String(hexChars)
    }
}
