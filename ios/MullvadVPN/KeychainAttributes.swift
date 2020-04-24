//
//  KeychainAttributes.swift
//  MullvadVPN
//
//  Created by pronebird on 22/04/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Security

extension Keychain {

    struct Attributes: KeychainAttributeEncodable, KeychainAttributeDecodable {
        var `class`: KeychainClass?
        var service: String?
        var account: String?
        var accessGroup: String?
        var creationDate: Date?
        var modificationDate: Date?

        var valueData: Data?
        var valuePersistentReference: Data?

        var `return`: Set<Keychain.Return>?
        var matchLimit: Keychain.MatchLimit?

        init() {}

        init(attributes: [CFString: Any]) {
            `class` = KeychainClass(attributes: attributes)
            service = attributes[kSecAttrService] as? String
            account = attributes[kSecAttrAccount] as? String
            accessGroup = attributes[kSecAttrAccessGroup] as? String
            creationDate = attributes[kSecAttrCreationDate] as? Date
            modificationDate = attributes[kSecAttrModificationDate] as? Date

            valueData = attributes[kSecValueData] as? Data
            valuePersistentReference = attributes[kSecValuePersistentRef] as? Data

            `return` = Set(attributes: attributes)
            matchLimit = Keychain.MatchLimit(attributes: attributes)
        }

        func updateKeychainAttributes(in attributes: inout [CFString: Any]) {
            `class`?.updateKeychainAttributes(in: &attributes)

            if let service = service {
                attributes[kSecAttrService] = service
            }

            if let account = account {
                attributes[kSecAttrAccount] = account
            }

            if let accessGroup = accessGroup {
                attributes[kSecAttrAccessGroup] = accessGroup
            }

            if let creationDate = creationDate {
                attributes[kSecAttrCreationDate] = creationDate
            }

            if let modificationDate = modificationDate {
                attributes[kSecAttrModificationDate] = modificationDate
            }

            if let valueData = valueData {
                attributes[kSecValueData] = valueData
            }

            if let valuePersistentReference = valuePersistentReference {
                attributes[kSecValuePersistentRef] = valuePersistentReference
            }

            `return`?.updateKeychainAttributes(in: &attributes)
            matchLimit?.updateKeychainAttributes(in: &attributes)
        }

    }

}
