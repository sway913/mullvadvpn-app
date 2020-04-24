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

enum TunnelConfigurationManagerError: Error {
    case encode(TunnelConfigurationCoder.Error)
    case decode(TunnelConfigurationCoder.Error)
    case addToKeychain(Keychain.Error)
    case updateKeychain(Keychain.Error)
    case removeKeychainItem(Keychain.Error)
    case getFromKeychain(Keychain.Error)
    case getPersistentKeychainRef(Keychain.Error)
}

enum TunnelConfigurationManager {}

extension TunnelConfigurationManager {

    static func save(configuration: TunnelConfiguration, account: String) -> Result<(), TunnelConfigurationManagerError> {
        TunnelConfigurationCoder.encode(tunnelConfig: configuration)
            .mapError { .encode($0) }
            .flatMap { (data) -> Result<(), TunnelConfigurationManagerError> in
                KeychainHelper.updateItem(account: account, data: data)
                    .flatMapError { (keychainError) -> Result<(), TunnelConfigurationManagerError> in
                        if case .itemNotFound = keychainError {
                            return KeychainHelper.addItem(account: account, data: data)
                                .mapError { .addToKeychain($0) }
                        } else {
                            return .failure(.updateKeychain(keychainError))
                        }
                }
        }
    }

    static func load(account: String) -> Result<TunnelConfiguration, TunnelConfigurationManagerError> {
        KeychainHelper.getItemData(account: account)
            .mapError { .getFromKeychain($0) }
            .flatMap { (data) in
                TunnelConfigurationCoder.decode(data: data)
                    .mapError { .decode($0) }
        }
    }

    static func load(persistentKeychainRef: Data) -> Result<TunnelConfiguration, TunnelConfigurationManagerError> {
        KeychainHelper.getItemData(persistentKeychainRef: persistentKeychainRef)
            .mapError { .getFromKeychain($0) }
            .flatMap { (data) in
                TunnelConfigurationCoder.decode(data: data)
                    .mapError { .decode($0) }
        }
    }

    static func remove(account: String) -> Result<(), TunnelConfigurationManagerError> {
        KeychainHelper.removeItem(account: account)
            .mapError { .removeKeychainItem($0) }
    }

    static func getPersistentKeychainRef(account: String) -> Result<Data, TunnelConfigurationManagerError> {
        KeychainHelper.getPersistentRef(account: account)
            .mapError { .getPersistentKeychainRef($0) }
    }

}

private enum KeychainHelper {}

private extension KeychainHelper {

    /// Get a persistent reference to the Keychain item for the given account token
    static func getPersistentRef(account: String) -> Keychain.Result<Data> {
        var query = Keychain.Attributes()
        query.class = .genericPassword
        query.account = account
        query.service = kServiceName
        query.return = [.persistentReference]

        return Keychain.findFirst(query: query).map { (attributes) -> Data in
            return attributes!.valueData!
        }
    }

    /// Get data associated with the given persistent Keychain reference
    static func getItemData(persistentKeychainRef: Data) -> Keychain.Result<Data> {
        var query = Keychain.Attributes()
        query.class = .genericPassword
        query.valuePersistentReference = persistentKeychainRef
        query.return = [.data]

        return Keychain.findFirst(query: query).map { (attributes) -> Data in
            return attributes!.valueData!
        }
    }

    /// Get data associated with the given account token
    static func getItemData(account: String) -> Keychain.Result<Data> {
        var query = Keychain.Attributes()
        query.class = .genericPassword
        query.account = account
        query.service = kServiceName
        query.return = [.data]

        return Keychain.findFirst(query: query).map { (attribute) -> Data in
            return attribute!.valueData!
        }
    }

    /// Store data in the Keychain and associate it with the given account token
    static func addItem(account: String, data: Data) -> Keychain.Result<()> {
        var attributes = Keychain.Attributes()
        attributes.class = .genericPassword
        attributes.valueData = data
        attributes.account = account
        attributes.service = kServiceName
        // Share the item with the application group
        attributes.accessGroup = ApplicationConfiguration.securityGroupIdentifier

        return Keychain.add(attributes)
            .map { _ in () }
    }

    /// Replace the data associated with the given account token.
    static func updateItem(account: String, data: Data) -> Keychain.Result<()> {
        var query = Keychain.Attributes()
        query.class = .genericPassword
        query.account = account
        query.service = kServiceName

        var update = Keychain.Attributes()
        update.valueData = data

        return Keychain.update(query: query, update: update)
    }

    /// Remove the data associated with the given account token
    static func removeItem(account: String) -> Keychain.Result<()> {
        var query = Keychain.Attributes()
        query.class = .genericPassword
        query.account = account
        query.service = kServiceName

        return Keychain.delete(query: query)
    }

}
