//
//  TunnelConfigurationManager.swift
//  MullvadVPN
//
//  Created by pronebird on 02/10/2019.
//  Copyright © 2019 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Security

/// Service name used for keychain items
private let kServiceName = "Mullvad VPN"

enum TunnelConfigurationManager {}

extension TunnelConfigurationManager {

    enum Error: Swift.Error {
        case encode(TunnelConfigurationCoder.Error)
        case decode(TunnelConfigurationCoder.Error)
        case addToKeychain(Keychain.Error)
        case updateKeychain(Keychain.Error)
        case removeKeychainItem(Keychain.Error)
        case getFromKeychain(Keychain.Error)
        case getPersistentKeychainRef(Keychain.Error)
    }

    enum SearchTerm {
        case accountToken(String)
        case persistentReference(Data)

        func apply(to attributes: inout Keychain.Attributes) {
            switch self {
            case .accountToken(let accountToken):
                attributes.account = accountToken
            case .persistentReference(let persistentReferenceData):
                attributes.valuePersistentReference = persistentReferenceData
            }
        }
    }

    static func modify(searchTerm: SearchTerm, using changeConfiguration: (inout TunnelConfiguration) -> Void) -> Result<(), TunnelConfigurationManager.Error> {
        var searchQuery = makeKeychainAttributes()
        searchQuery.return = [.attributes, .data]
        searchTerm.apply(to: &searchQuery)

        while true {
            let result = Keychain.findFirst(query: searchQuery)
                .mapError { TunnelConfigurationManager.Error.getFromKeychain($0) }
                .flatMap { (itemAttributes) -> Result<(), TunnelConfigurationManager.Error> in
                    let itemAttributes = itemAttributes!
                    let serializedData = itemAttributes.valueData!
                    let modificationDate = itemAttributes.modificationDate!

                    return Self.decode(data: serializedData)
                        .flatMap { (tunnelConfig) -> Result<(), TunnelConfigurationManager.Error> in
                            var tunnelConfig = tunnelConfig
                            changeConfiguration(&tunnelConfig)

                            return Self.encode(tunnelConfig: tunnelConfig)
                                .flatMap { (newData) -> Result<(), TunnelConfigurationManager.Error> in
                                    var searchQuery = Keychain.Attributes()
                                    searchQuery.class = .genericPassword
                                    searchQuery.service = kServiceName
                                    searchTerm.apply(to: &searchQuery)

                                    // provide last known modification date to prevent overwriting
                                    // the item
                                    searchQuery.modificationDate = modificationDate

                                    var updateAttributes = Keychain.Attributes()
                                    updateAttributes.valueData = newData

                                    return Keychain.update(query: searchQuery, update: updateAttributes)
                                        .mapError { TunnelConfigurationManager.Error.updateKeychain($0) }
                            }
                        }
            }

            if case .failure(.updateKeychain(.itemNotFound)) = result  {
                continue
            }

            return result
        }
    }

    static func load(searchTerm: SearchTerm) -> Result<TunnelConfiguration, TunnelConfigurationManager.Error> {
        var query = makeKeychainAttributes()
        query.return = [.data]
        searchTerm.apply(to: &query)

        return Keychain.findFirst(query: query)
            .mapError { .getFromKeychain($0) }
            .flatMap { (attributes) in
                return Self.decode(data: attributes!.valueData!)
        }
    }

    static func add(configuration: TunnelConfiguration, account: String) -> Result<(), TunnelConfigurationManager.Error> {
        Self.encode(tunnelConfig: configuration)
            .flatMap { (data) -> Result<(), TunnelConfigurationManager.Error> in
                var attributes = makeKeychainAttributes()
                attributes.account = account
                attributes.valueData = data
                // Share the item with the application group
                attributes.accessGroup = ApplicationConfiguration.securityGroupIdentifier

                return Keychain.add(attributes)
                    .mapError { .addToKeychain($0) }
                    .map { _ in () }
        }
    }

    static func remove(searchTerm: SearchTerm) -> Result<(), TunnelConfigurationManager.Error> {
        var query = makeKeychainAttributes()
        searchTerm.apply(to: &query)

        return Keychain.delete(query: query)
            .mapError { .removeKeychainItem($0) }
    }

    /// Get a persistent reference to the Keychain item for the given account token
    static func getPersistentKeychainRef(account: String) -> Result<Data, TunnelConfigurationManager.Error> {
        var query = makeKeychainAttributes()
        query.account = account
        query.return = [.persistentReference]

        return Keychain.findFirst(query: query)
            .mapError { .getPersistentKeychainRef($0) }
            .map { (attributes) -> Data in
                return attributes!.valueData!
        }
    }

    /// Returns common used Keychain attributes with class and service set
    private static func makeKeychainAttributes() -> Keychain.Attributes {
        var attributes = Keychain.Attributes()
        attributes.class = .genericPassword
        attributes.service = kServiceName
        return attributes
    }

    private static func encode(tunnelConfig: TunnelConfiguration) -> Result<Data, TunnelConfigurationManager.Error> {
        TunnelConfigurationCoder.encode(tunnelConfig: tunnelConfig)
            .mapError { TunnelConfigurationManager.Error.encode($0) }
    }

    private static func decode(data: Data) -> Result<TunnelConfiguration, TunnelConfigurationManager.Error> {
        TunnelConfigurationCoder.decode(data: data)
            .mapError { TunnelConfigurationManager.Error.decode($0) }
    }
}
