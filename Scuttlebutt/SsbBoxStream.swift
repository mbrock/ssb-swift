//
//  SsbBoxStream.swift
//  Scuttlebutt
//
//  Created by Mikael Brockman on 2018-09-24.
//  Copyright © 2018 Mikael Brockman. All rights reserved.
//

import Foundation
import Network
import Sodium

func incrementNonce(_ nonce: inout Bytes) -> () {
    var i = nonce.count - 1
    while i >= 0 && nonce[i] == 0xff {
        nonce[i] = 0
        i -= 1
    }
    if i >= 0 {
        nonce[i] += 1
    }
}

class SsbBoxStream {
    let connection: NWConnection
    let secretBox: SecretBox
    let key: Bytes
    var nonce: Bytes
    
    init(connection: NWConnection, secretBox: SecretBox, key: Bytes, nonce: Bytes) {
        self.connection = connection
        self.secretBox = secretBox
        self.key = key
        self.nonce = nonce
    }
    
    func send(_ msg: Bytes, _ completion: @escaping ((NWError?) -> ())) {
        let nonce1 = nonce
        incrementNonce(&nonce)
        let encrypted_body = secretBox.seal(message: msg, secretKey: key, nonce: nonce)!
        assert(encrypted_body.mac.count == 16)
        let size_be = [UInt8(msg.count >> 8), UInt8(msg.count & 0xff)]
        let header = secretBox.seal(message: size_be + encrypted_body.mac, secretKey: key, nonce: nonce1)!
        let payload = header.mac + header.cipherText + encrypted_body.cipherText
        incrementNonce(&nonce)
        connection.send(content: Data(payload), completion: .contentProcessed(completion))
    }
}

class SsbUnboxStream {
    let connection: NWConnection
    let secretBox: SecretBox
    let key: Bytes
    var nonce: Bytes
    
    init(connection: NWConnection, secretBox: SecretBox, key: Bytes, nonce: Bytes) {
        self.connection = connection
        self.secretBox = secretBox
        self.key = key
        self.nonce = nonce
    }
    
    func read(_ completion: @escaping ((Bytes?, NWError?) -> ())) {
        connection.receive(minimumIncompleteLength: 34, maximumLength: 34) {
            (data, _, isComplete, error) in
            if let error = error {
                completion(nil, error)
            } else {
                if let data = data {
                    assert(data.count == 34)
                    let header = self.secretBox.open(
                        authenticatedCipherText: Bytes(data),
                        secretKey: self.key,
                        nonce: self.nonce
                        )!
                    if header.count == 18 && header.allSatisfy({ $0 == 0 }) {
                        completion(nil, nil)
                    } else {
                        incrementNonce(&self.nonce)
                        let size = Int(header[0]) << 8 + Int(header[1])
                        self.connection.receive(minimumIncompleteLength: size, maximumLength: size) {
                            (data2, _, isComplete2, error2) in
                            if let error2 = error2 {
                                completion(nil, error2)
                            } else {
                                let body = self.secretBox.open(
                                    cipherText: Bytes(data2!),
                                    secretKey: self.key,
                                    nonce: self.nonce,
                                    mac: Bytes(header.suffix(from: 2))
                                    )!
                                incrementNonce(&self.nonce)
                                completion(body, nil)
                            }
                        }
                    }
                } else {
                    completion(nil, nil)
                }
            }
        }
    }
}
