//
//  Ssb.swift
//  Scuttlebutt
//
//  Created by Mikael Brockman on 2018-09-24.
//  Copyright © 2018 Mikael Brockman. All rights reserved.
//

import Foundation

enum SsbError {
    case NetworkError(Any)
    case CryptoError(String)
    case ProtocolError(String)
}
