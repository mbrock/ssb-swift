//
//  SsbEventStore.swift
//  Scuttlebutt
//
//  Created by Mikael Brockman on 2018-09-25.
//  Copyright © 2018 Mikael Brockman. All rights reserved.
//

import Foundation
import JSON

// We want to store the whole history of RPC events within the app,
// basically as a backup for generating other databases.
//
// The sequence contains both sent and received RPC calls interleaved
// in a reasonable way.  A response shall never precede its request.

typealias SsbPublicKey = Bytes
typealias SsbPrivateKey = Bytes

struct SsbKeypair {
    let pk: SsbPublicKey
    let sk: SsbPrivateKey
}

extension JSON {
    
}
