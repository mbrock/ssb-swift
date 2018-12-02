//
//  SsbRpc.swift
//  Scuttlebutt
//
//  Created by Mikael Brockman on 2018-09-24.
//  Copyright © 2018 Mikael Brockman. All rights reserved.
//

import Foundation
import Network

import JSON

typealias Bytes = Array<UInt8>

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

enum Either<E, A> {
    case Left(E)
    case Right(A)
}

class RPCOutputStream {
    let sink: SsbBoxStream
    
    init(sink: SsbBoxStream) {
        self.sink = sink
    }
    
    func send(_ req: Request, _ completion: @escaping ((SsbError?) -> ())) {
        // XXX: this doesn't split large messages
        let bytes = serialize(req)
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
            return make(Bytes((try! json.serialized(options: JSON.Serializer.Option.prettyPrint)).data(using: .utf8)!))
        }
    }
}

class RPCInputStream {
    let source: SsbUnboxStream
    
    enum State {
        case ReadingHeader(Bytes)
        case ReadingBody(IsStream, IsEnd, Int32, BodyType, Bytes, UInt32)
    }
    
    var state: State = .ReadingHeader(Bytes([]))
    
    init(source: SsbUnboxStream) {
        self.source = source
    }
    
    func read(_ completion: @escaping (Either<SsbError, Request>) -> ()) {
        source.read() { (data, error) in
            if let error = error {
                completion(.Left(.NetworkError(error)))
            } else {
                guard let data = data else {
                    return completion(.Left(.ProtocolError("eof")))
                }
                
                switch self.state {
                case .ReadingBody(
                    let isStream, let isEnd, let requestNumber,
                    let bodyType, let bytes, let bodyLength
                    ):
                    let buffer = bytes + data
                    if buffer.count >= bodyLength {
                        self.state = .ReadingHeader(Bytes(buffer.suffix(from: Int(bodyLength))))
                        
                        let bodyBytes = Bytes(buffer.prefix(Int(bodyLength)))
                        var body: Request.Body
                        switch bodyType {
                        case .Binary: body = .Binary(bodyBytes)
                        case .String: body = .String(String(bytes: bodyBytes, encoding: .utf8)!)
                        case .JSON: body = .JSON(try! JSON.Parser.parse(Data(bodyBytes), options: JSON.Parser.Option.allowFragments))
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
                        let requestNumber = Int32(bitPattern: bigEndian4(chunk, 5))
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
        }
    }
}
