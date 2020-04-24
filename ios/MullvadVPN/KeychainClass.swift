//
//  KeychainClass.swift
//  MullvadVPN
//
//  Created by pronebird on 24/04/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Security

extension Keychain {
    
    enum KeychainClass: RawRepresentable, KeychainAttributeDecodable, KeychainAttributeEncodable {
        case genericPassword
        case internetPassword

        var rawValue: CFString {
            switch self {
            case .genericPassword:
                return kSecClassGenericPassword
            case .internetPassword:
                return kSecClassInternetPassword
            }
        }

        init?(rawValue: CFString) {
            switch rawValue {
            case kSecClassGenericPassword:
                self = .genericPassword
            case kSecClassInternetPassword:
                self = .internetPassword
            default:
                return nil
            }
        }

        init?(attributes: [CFString: Any]) {
            if let rawValue = attributes[kSecClass] as? String {
                self.init(rawValue: rawValue as CFString)
            } else {
                return nil
            }
        }

        func updateKeychainAttributes(in attributes: inout [CFString : Any]) {
            attributes[kSecClass] = rawValue
        }
    }

}
