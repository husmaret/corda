/*
 * Copyright 2015 Distributed Ledger Group LLC.  Distributed as Licensed Company IP to DLG Group Members
 * pursuant to the August 7, 2015 Advisory Services Agreement and subject to the Company IP License terms
 * set forth therein.
 *
 * All other rights reserved.
 */
package core.node

import core.Party
import core.messaging.SingleMessageRecipient
import core.node.services.ServiceType

/**
 * Info about a network node that acts on behalf of some form of contract party.
 */
data class NodeInfo(val address: SingleMessageRecipient, val identity: Party,
                    var advertisedServices: Set<ServiceType> = emptySet(),
                    val physicalLocation: PhysicalLocation? = null)