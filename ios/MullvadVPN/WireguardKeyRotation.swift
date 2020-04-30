//
//  WireGuardKeyRotation.swift
//  MullvadVPN
//
//  Created by pronebird on 30/04/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Combine

class WireguardKeyRotation {

    enum Error: Swift.Error {
        /// A failure to read the public Wireguard key from Keychain
        case readPublicWireguardKey(TunnelConfigurationManager.Error)

        /// A failure to replace the public Wireguard key
        case replaceWireguardKey(MullvadAPI.Error)

        /// A failure to update tunnel configuration
        case updateTunnelConfiguration(TunnelConfigurationManager.Error)
    }

    private let apiClient: MullvadAPI

    init(apiClient: MullvadAPI) {
        self.apiClient = apiClient
    }

    func rotatePrivateKey(searchTerm: TunnelConfigurationManager.SearchTerm) -> AnyPublisher<(), Error> {
        let newPrivateKey = WireguardPrivateKey()

        return TunnelConfigurationManager.load(searchTerm: searchTerm)
            .mapError { .readPublicWireguardKey($0) }
            .publisher
            .flatMap { (keychainEntry) -> AnyPublisher<(), Error> in
                let tunnelConfiguration = keychainEntry.tunnelConfiguration
                let oldPublicKey = tunnelConfiguration.interface.privateKey.publicKey

                return self.apiClient.replaceWireguardKey(
                    accountToken: keychainEntry.accountToken,
                    oldPublicKey: oldPublicKey.rawRepresentation,
                    newPublicKey: newPrivateKey.publicKey.rawRepresentation)
                    .mapError {  .replaceWireguardKey($0) }
                    .flatMap { (addresses) in
                        TunnelConfigurationManager
                            .update(searchTerm: searchTerm)
                            { (tunnelConfiguration) in
                                tunnelConfiguration.interface.privateKey = newPrivateKey
                                tunnelConfiguration.interface.addresses = [
                                    addresses.ipv4Address,
                                    addresses.ipv6Address
                                ]
                        }
                        .mapError { .updateTunnelConfiguration($0) }
                        .publisher
                }.eraseToAnyPublisher()
        }.eraseToAnyPublisher()
    }

}
