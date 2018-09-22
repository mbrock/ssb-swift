//
//  Handshake.swift
//  Scuttlebutt
//
//  Created by Mikael Brockman on 2018-09-21.
//  Copyright © 2018 Mikael Brockman. All rights reserved.
//

import Foundation
import Sodium
import Network
import Dispatch
import SwiftyJSON

extension String {
    func decodeBase64() -> Bytes? {
        guard let data = Data(base64Encoded: self) else { return nil }
        return Bytes(data)
    }
}

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

class BoxStream {
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
        let encrypted_body = secretBox.seal(message: msg, secretKey: key, nonce: nonce)!
        assert(encrypted_body.mac.count == 16)
        incrementNonce(&nonce)
        let size_be = [UInt8(msg.count >> 8), UInt8(msg.count & 0xff)]
        let header = secretBox.seal(message: size_be + encrypted_body.mac, secretKey: key, nonce: nonce)!
        incrementNonce(&nonce)
        let payload = header.mac + header.cipherText + encrypted_body.cipherText
        connection.send(content: Data(payload), completion: .contentProcessed(completion))
    }
}

class UnboxStream {
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
        connection.receive(minimumIncompleteLength: 34, maximumLength: 34, completion: {
            (data, _, isComplete, error) in
            if let error = error {
                completion(nil, error)
            } else {
                if let data = data {
                    assert(data.count == 34)
                    print("data", data.base64EncodedString())
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
                        self.connection.receive(minimumIncompleteLength: size, maximumLength: size, completion: {
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
                        })
                    }
                } else {
                    print("stream over", isComplete)
                    completion(nil, nil)
                }
            }
        })
    }
}

enum IsStream { case IsStream; case IsNotStream }
enum IsEnd { case IsEnd; case IsNotEnd }
enum BodyType: UInt8 { case Binary = 0; case String; case JSON }

struct Request {
    enum Body {
        case Binary(Bytes)
        case String(String)
        case JSON(JSON)
    }
    
    let isStream: IsStream
    let isEnd: IsEnd
    let number: Int32
    let body: Body
}

enum Error {
    case NetworkError(NWError)
    case CryptoError(String)
    case ProtocolError(String)
}

enum Either<E, A> {
    case Left(E)
    case Right(A)
}

class RPCOutputStream {
    let sink: BoxStream
    
    init(sink: BoxStream) {
        self.sink = sink
    }
    
    func send(_ req: Request, _ completion: @escaping ((Error?) -> ())) {
        // XXX: this doesn't split large messages
        let bytes = serialize(req)
        print("sending", bytes)
        sink.send(bytes, { (error) in
            if let error = error {
                completion(.NetworkError(error))
            } else {
                completion(nil)
            }
        })
    }
    
    func serialize(_ req: Request) -> Bytes {
        var flags = UInt8(0)
        if req.isStream == .IsStream { flags += 8 }
        if req.isEnd    == .IsEnd    { flags += 4 }
        
        func bigEndian4(_ x: UInt32) -> Bytes {
            return [
                UInt8((x >> 24) & 0xff),
                UInt8((x >> 16) & 0xff),
                UInt8((x >> 8)  & 0xff),
                UInt8(x       & 0xff)
            ]
        }

        func make(_ body: Bytes) -> Bytes {
            return (
                [flags]
                    + bigEndian4(UInt32(body.count))
                    + bigEndian4(UInt32(bitPattern: req.number))
                    + body
            )
        }
        
        switch req.body {
        case .Binary(let bytes):
            return make(bytes)
            
        case .String(let string):
            flags += 1
            return make(Bytes(string.data(using: .utf8)!))
            
        case .JSON(let json):
            flags += 2
            return make(Bytes(try! json.rawData()))
        }
    }
}

class RPCInputStream {
    let source: UnboxStream
    
    enum State {
        case ReadingHeader(Bytes)
        case ReadingBody(IsStream, IsEnd, Int32, BodyType, Bytes, UInt32)
    }
    
    var state: State = .ReadingHeader(Bytes([]))
    
    init(source: UnboxStream) {
        self.source = source
    }
    
    func read(_ completion: @escaping (Either<Error, Request>) -> ()) {
        source.read({ (data, error) in
            if let error = error {
                completion(.Left(.NetworkError(error)))
            } else {
                guard let data = data else {
                    return completion(.Left(.ProtocolError("eof")))
                }
                
                print("state",  self.state, "data", data)

                switch self.state {
                case .ReadingBody(
                    let isStream, let isEnd, let requestNumber,
                    let bodyType, let bytes, let bodyLength
                ):
                    let buffer = data + bytes
                    print("buffer", bodyLength, buffer)
                    if buffer.count >= bodyLength {
                        self.state = .ReadingHeader(Bytes(buffer.suffix(from: Int(bodyLength))))
                        
                        let bodyBytes = Bytes(buffer.prefix(Int(bodyLength)))
                        print("bodybytes", bodyBytes)
                        var body: Request.Body
                        switch bodyType {
                        case .Binary: body = .Binary(bodyBytes)
                        case .String: body = .String(String(bytes: bodyBytes, encoding: .utf8)!)
                        case .JSON: body = .JSON(JSON(Data(bodyBytes)))
                        }
                        
                        return completion(.Right(Request(
                            isStream: isStream, isEnd: isEnd, number: requestNumber, body: body
                        )))
                    } else {
                        self.state = .ReadingBody(isStream, isEnd, requestNumber, bodyType, buffer, bodyLength)
                    }
                    
                case .ReadingHeader(let bytes):
                    func bigEndian4(_ xs: Array<UInt8>, _ i: Int) -> UInt32 {
                        var x: UInt32 = 0
                        for j in 0..<4 {
                            x += UInt32(xs[i + j]) << (8 * UInt32(3 - j))
                        }
                        return x
                    }
                    
                    let chunk = bytes + data
                    if chunk.count >= 9 {
                        let flags = chunk[0]
                        let bodyLength = bigEndian4(chunk, 1)
                        let requestNumber = Int32(bigEndian4(chunk, 5))
                        let suffix = Array(chunk.suffix(from: 9))
                        
                        self.state = .ReadingBody(
                            flags & 8 > 0 ? .IsStream : .IsNotStream,
                            flags & 4 > 0 ? .IsEnd : .IsNotEnd,
                            requestNumber,
                            BodyType(rawValue: flags & 3)!,
                            suffix,
                            bodyLength
                        )
                    } else {
                        self.state = .ReadingHeader(chunk)
                    }
                }
                
                self.read(completion)
            }
        })
    }
}

public func foo() {
    let sodium = Sodium()
    
    func tag(_ message: Bytes, _ secretKey: Bytes) -> Bytes? {
        return sodium.auth.tag(message: message, secretKey: secretKey)
    }
    
    let A = sodium.sign.keyPair()!
    let a = sodium.box.keyPair()!
    let A_pk = A.publicKey
    let A_sk = A.secretKey
    let a_pk = a.publicKey
    let a_sk = a.secretKey
    
    let B_pk =
        "uMiN0TRVMGVNTQUb6KCbiOi/8UQYcyojiA83rCghxGo=".decodeBase64()!
    let N =
        "1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=".decodeBase64()!
    
    let client_hmac = tag(a_pk, N)!.prefix(upTo: 32)
    
    let connection = NWConnection(
        host: "ssb.learningsocieties.org", port: 8008, using: .tcp)
    
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
        send(tag(a_pk, N)! + a_pk, { (error) in
            if let error = error {
                print("error in step 1", error)
            } else {
                step2()
            }
        })
        print("waiting for send to complete")
    }
    
    func step2() {
        readPacket(64, {
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
        })
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
        
        send(message, {(error) in
            if let error = error {
                print(error)
            } else {
                step4(sig_A: sig_A, b_pk: b_pk, ab: ab, aB: aB, server_hmac: server_hmac)
            }
        })
    }
    
    func step4(sig_A: Bytes, b_pk: Bytes, ab: Bytes, aB: Bytes, server_hmac: Bytes) {
        readPacket(80, {
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
                    let boxStream = BoxStream(
                        connection: connection,
                        secretBox: sodium.secretBox,
                        key: sha256(sha256(sha256(N + ab + aB + Ab)) + B_pk),
                        nonce: Bytes(server_hmac.prefix(upTo: 24))
                    )
                    let unboxStream = UnboxStream(
                        connection: connection,
                        secretBox: sodium.secretBox,
                        key: sha256(sha256(sha256(N + ab + aB + Ab)) + A_pk),
                        nonce: Bytes(client_hmac.prefix(upTo: 24))
                    )
                    
                    print(boxStream, unboxStream)
                    
                    let rpcInput = RPCInputStream(source: unboxStream)
                    let rpcOutput = RPCOutputStream(sink: boxStream)
                    func loop() {
                        rpcInput.read({
                            switch $0 {
                            case .Left(let e):
                                print(e)
                                return
                            case .Right(let rpc):
                                print(rpc.body)
                                switch rpc.body {
                                case .JSON(let json):
                                    let name = json["name"].arrayValue.map({$0.stringValue})
                                    switch name {
                                    case ["blobs", "createWants"]:
                                        let response = Request(
                                            isStream: .IsStream,
                                            isEnd: .IsNotEnd,
                                            number: -rpc.number,
                                            body: .JSON([:]))
                                        rpcOutput.send(response, {
                                            print("finished RPC", $0.debugDescription)
                                            let gimme = JSON([
                                                "name": JSON(["createHistoryStream"]),
                                                "type": JSON("source"),
                                                "args": JSON([["id": "@oovEFjYs7F5m9RBPiK+gLtKDGL532sTStjiCLyJjqz0=.ed25519"]])
                                            ])
                                            print("json", String(bytes: try! gimme.rawData(), encoding: .utf8)!)
                                            rpcOutput.send(
                                                Request(isStream: .IsStream, isEnd: .IsNotEnd, number: 1, body: .JSON(gimme)),
                                                {print("finished gimme", $0.debugDescription)}
                                            )
                                        })
                                    default:
                                        print("unknown RPC")
                                    }
                                default:
                                    print("unknown RPC")
                                }
                                loop()
                            }
                        })
                    }
                    
                    loop()
                } else {
                    print("failed to verify server accept")
                }
            }
        })
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
            maximumLength: count,
            completion: {
                (content, _, complete, error) in
                completion(content, complete, error)
            }
        )
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
