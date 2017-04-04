package net.corda.core.crypto

import java.security.Provider

/**
 * Created by rossnicoll on 04/04/2017.
 */
// TODO: Write info
class CompositeProvider : Provider("X-Corda", 0.1, "") {
    init {
        this.putService(CompositeSignature.getService(this))
    }
}