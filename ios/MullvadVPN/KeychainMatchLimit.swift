//
//  KeychainMatchLimit.swift
//  MullvadVPN
//
//  Created by pronebird on 24/04/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Security

extension Keychain {
    enum MatchLimit: RawRepresentable, KeychainAttributeDecodable, KeychainAttributeEncodable {
        case one
        case all

        var rawValue: CFString {
            switch self {
            case .one:
                return kSecMatchLimitOne
            case .all:
                return kSecMatchLimitAll
            }
        }

        init?(rawValue: CFString) {
            switch rawValue {
            case kSecMatchLimitOne:
                self = .one
            case kSecMatchLimitAll:
                self = .all
            default:
                return nil
            }
        }

        init?(attributes: [CFString : Any]) {
            if let rawValue = attributes[kSecMatchLimit] as? String {
                self.init(rawValue: rawValue as CFString)
            } else {
                return nil
            }
        }

        func updateKeychainAttributes(in attributes: inout [CFString : Any]) {
            attributes[kSecMatchLimit] = rawValue
        }
    }
}
