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
import JSON

struct Params {
    let pk: String
    let address: NWEndpoint.Host
    let port: NWEndpoint.Port
}

public func foo(showMarkdown: @escaping (String) -> ()) {
    let localParams = Params(
        pk: "oovEFjYs7F5m9RBPiK+gLtKDGL532sTStjiCLyJjqz0=",
        address: "192.168.0.101",
        port: 8008)
    
    let _ = Params(
        pk: "uMiN0TRVMGVNTQUb6KCbiOi/8UQYcyojiA83rCghxGo=",
        address: "ssb.learningsocieties.org",
        port: 8008)
    
    performSsbHandshake(sodium: Sodium(), params: localParams) {
        switch $0 {
        case .Left(let error):
            print(error)
        case .Right(let (rpcInputStream, rpcOutputStream)):
            func loop() {
                rpcInputStream.read {
                    switch $0 {
                    case .Left(let e):
                        print(e)
                        return
                    case .Right(let rpc):
                        switch rpc.body {
                        case .JSON(let json):
                            let name = json["name"].array?.map({$0.string})
                            switch name {
                            case ["blobs", "createWants"]:
                                let response = Request(
                                    isStream: .IsStream,
                                    isEnd: .IsNotEnd,
                                    number: -rpc.number,
                                    body: .JSON([:]))
                                rpcOutputStream.send(response) { _ in
                                    let gimme: JSON = [
                                        "name": ["createHistoryStream"] as JSON,
                                        "type": "source",
                                        "args": [["id": "@oovEFjYs7F5m9RBPiK+gLtKDGL532sTStjiCLyJjqz0=.ed25519"] as JSON] as JSON
                                        ]
                                    rpcOutputStream.send(
                                        Request(isStream: .IsStream, isEnd: .IsNotEnd, number: 1, body: .JSON(gimme))
                                    ) {
                                        print("finished gimme", $0.debugDescription)
                                    }
                                }
                            default:
                                
                                if let text = json["value"]["content"]["text"].string {
                                    showMarkdown(text)
                                }
                            }
                        default:
                            print("unknown RPC")
                        }
                        loop()
                    }
                }
            }
            loop()
        }
    }
}
