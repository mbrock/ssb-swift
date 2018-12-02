//
//  SSBMessageTableViewCell.swift
//  Scuttlebutt
//
//  Created by Mikael Brockman on 2018-09-23.
//  Copyright © 2018 Mikael Brockman. All rights reserved.
//

import UIKit

class SsbMessageTableViewCell: UITableViewCell {
    
    @IBOutlet weak var label: UILabel!
    
    override func awakeFromNib() {
        super.awakeFromNib()
        // Initialization code
    }

    override func setSelected(_ selected: Bool, animated: Bool) {
        super.setSelected(selected, animated: animated)

        // Configure the view for the selected state
    }

}
