//
//  SsbUtilities.swift
//  Scuttlebutt
//
//  Created by Mikael Brockman on 2018-09-24.
//  Copyright © 2018 Mikael Brockman. All rights reserved.
//

import Foundation

func decodeBase64(_ string: String) -> Bytes? {
    if let data = Data(base64Encoded: string) {
        return Bytes(data)
    } else {
        return nil
    }
}
