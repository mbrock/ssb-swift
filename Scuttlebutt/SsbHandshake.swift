//
//  SsbHandshake.swift
//  Scuttlebutt
//
//  Created by Mikael Brockman on 2018-09-24.
//  Copyright © 2018 Mikael Brockman. All rights reserved.
//

import Foundation
import Sodium
import Network

func performSsbHandshake(
    sodium: Sodium,
    params: Params,
    completion: @escaping (Either<SsbError, (RPCInputStream, RPCOutputStream)>) -> ()
    ) {
    
    func tag(_ message: Bytes, _ secretKey: Bytes) -> Bytes? {
        return sodium.auth.tag(message: message, secretKey: secretKey)
    }
    
    let A = sodium.sign.keyPair()!
    let a = sodium.box.keyPair()!
    let A_pk = A.publicKey
    let A_sk = A.secretKey
    let a_pk = a.publicKey
    let a_sk = a.secretKey
    
    let B_pk = decodeBase64(params.pk)!
    let N = decodeBase64(
        "1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=")!
    
    let client_hmac = tag(a_pk, N)!.prefix(upTo: 32)
    
    let connection = NWConnection(
        host: params.address, port: params.port, using: .tcp)
    
    print("waiting for connection")
    
    connection.stateUpdateHandler = { (newState) in
        switch (newState) {
        case .ready:
            print("connection ready")
            step1()
        case .waiting(_):
            print("connection waiting")
        case .failed(_):
            print("connection failed")
        default:
            break
        }
    }
    
    connection.start(queue: DispatchQueue.main)
    
    func step1() {
        send(tag(a_pk, N)! + a_pk) { (error) in
            if let error = error {
                print("error in step 1", error)
            } else {
                step2()
            }
        }
        print("waiting for send to complete")
    }
    
    func step2() {
        readPacket(64) {
            (content, isComplete, error) in
            if let error = error {
                print(error)
            } else {
                assert(content?.count == 64)
                let hmac = Bytes(content!.prefix(upTo: 32))
                let b_pk = Bytes(content!.suffix(from: 32))
                if sodium.auth.verify(message: b_pk, secretKey: N, tag: hmac) {
                    step3(b_pk: b_pk, server_hmac: hmac)
                } else {
                    print("authentication error")
                }
            }
        }
    }
    
    func step3(b_pk: Bytes, server_hmac: Bytes) {
        let ab = scalarmult(a_sk, b_pk)!
        let aB = scalarmult(a_sk, curvify_pk(B_pk)!)!
        
        let sig_A = sign(N + B_pk + sha256(ab), A_sk)!
        
        let message = seal(
            sig_A + A_pk,
            sha256(N + ab + aB),
            nonce: Bytes(repeating: 0, count: 24)
            )!
        
        send(message) { (error) in
            if let error = error {
                print(error)
            } else {
                step4(sig_A: sig_A, b_pk: b_pk, ab: ab, aB: aB, server_hmac: server_hmac)
            }
        }
    }
    
    func step4(sig_A: Bytes, b_pk: Bytes, ab: Bytes, aB: Bytes, server_hmac: Bytes) {
        readPacket(80) {
            (content, isComplete, error) in
            if let error = error {
                print(error)
            } else {
                assert(content?.count == 80)
                
                let n = curvify_sk(A_sk)!
                let Ab = scalarmult(n, b_pk)!
                let sig_B = open(content!, sha256(N + ab + aB + Ab), nonce: Bytes(repeating: 0, count: 24))!
                
                if verify(N + sig_A + A_pk + ab.sha256, key: B_pk, sig: sig_B) {
                    print("verified server accept")
                    let boxStream = SsbBoxStream(
                        connection: connection,
                        secretBox: sodium.secretBox,
                        key: sha256(sha256(sha256(N + ab + aB + Ab)) + B_pk),
                        nonce: Bytes(server_hmac.prefix(upTo: 24))
                    )
                    let unboxStream = SsbUnboxStream(
                        connection: connection,
                        secretBox: sodium.secretBox,
                        key: sha256(sha256(sha256(N + ab + aB + Ab)) + A_pk),
                        nonce: Bytes(client_hmac.prefix(upTo: 24))
                    )
                    
                    let rpcInput = RPCInputStream(source: unboxStream)
                    let rpcOutput = RPCOutputStream(sink: boxStream)
                    
                    completion(.Right((rpcInput, rpcOutput)))
                } else {
                    print("failed to verify server accept")
                }
            }
        }
    }
    
    func verify(_ msg: Bytes, key: Bytes, sig: Bytes) -> Bool {
        return sodium.sign.verify(message: msg, publicKey: key, signature: sig)
    }
    
    func send(_ bytes: Bytes, _ completion: @escaping (NWError?) -> ()) {
        connection.send(content: Data(bytes), completion: .contentProcessed {
            (error) in completion(error)
            })
    }
    
    func readPacket(_ count: Int, _ completion: @escaping (Data?, Bool, NWError?) -> ()) {
        connection.receive(
            minimumIncompleteLength: count,
            maximumLength: count
        ) {
            (content, _, complete, error) in
            completion(content, complete, error)
        }
    }
    
    func scalarmult(_ n: Bytes, _ p: Bytes) -> Bytes? {
        return sodium.secretBox.scalarmult(n: n, p: p)
    }
    
    func curvify_pk(_ key: Bytes) -> Bytes? {
        return sodium.sign.ed25519_pk_to_curve25519(publicKey: key)
    }
    
    func curvify_sk(_ key: Bytes) -> Bytes? {
        return sodium.sign.ed25519_sk_to_curve25519(secretKey: key)
    }
    
    func sign(_ msg: Bytes, _ key: Bytes) -> Bytes? {
        return sodium.sign.signature(message: msg, secretKey: key)
    }
    
    func seal(_ msg: Bytes, _ key: Bytes, nonce: Bytes) -> Bytes? {
        if let x = sodium.secretBox.seal(message: msg, secretKey: key, nonce: nonce) {
            return x.mac + x.cipherText
        } else {
            return nil
        }
    }
    
    func open(_ msg: Data, _ key: Bytes, nonce: Bytes) -> Bytes? {
        return sodium.secretBox.open(
            authenticatedCipherText: Bytes(msg), secretKey: key, nonce: nonce
        )
    }
    
    func sha256(_ x: Bytes) -> Bytes {
        return x.sha256
    }
    
}
