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

    enum PushWireguardKeyError: Swift.Error {
        case transport(MullvadAPI.Error)
        case server(MullvadAPI.ResponseError)
    }

    enum Error: Swift.Error {
        /// A failure to read the public Wireguard key from Keychain
        case readPublicWireguardKey(TunnelConfigurationManager.Error)

        /// A failure to replace the public Wireguard key
        case replaceWireguardKey(PushWireguardKeyError)

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
                    .mapError { (networkError) -> Error in
                        return .replaceWireguardKey(.transport(networkError))
                }.flatMap { (response: MullvadAPI.Response<WireguardAssociatedAddresses>) in
                    return response.result.publisher
                        .mapError { (serverError) -> Error in
                            return .replaceWireguardKey(.server(serverError))
                    }
                }
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
