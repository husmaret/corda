package net.corda.node.services.identity

import net.corda.core.contracts.PartyAndReference
import net.corda.core.crypto.AnonymousParty
import net.corda.core.crypto.CompositeKey
import net.corda.core.crypto.Party
import net.corda.core.crypto.toStringShort
import net.corda.core.node.services.IdentityService
import net.corda.core.serialization.SingletonSerializeAsToken
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.trace
import java.security.PublicKey
import java.security.cert.CertPath
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.annotation.concurrent.ThreadSafe

/**
 * Simple identity service which caches parties and provides functionality for efficient lookup.
 */
@ThreadSafe
class InMemoryIdentityService() : SingletonSerializeAsToken(), IdentityService {
    companion object {
        private val log = loggerFor<InMemoryIdentityService>()
    }

    private val keyToParties = ConcurrentHashMap<PublicKey, Party>()
    private val nameToParties = ConcurrentHashMap<String, Party>()
    private val partyToPath = ConcurrentHashMap<AnonymousParty, CertPath>()

    override fun registerIdentity(party: Party) {
        log.trace { "Registering identity ${party}" }
        keyToParties[party.owningKey] = party
        nameToParties[party.name] = party
    }

    // We give the caller a copy of the data set to avoid any locking problems
    override fun getAllIdentities(): Iterable<Party> = ArrayList(keyToParties.values)

    override fun partyFromKey(key: PublicKey): Party? = keyToParties[key]
    override fun partyFromName(name: String): Party? = nameToParties[name]
    override fun partyFromAnonymous(party: AnonymousParty): Party? = partyFromKey(party.owningKey)
    override fun partyFromAnonymous(partyRef: PartyAndReference) = partyFromAnonymous(partyRef.party)

    override fun assertOwnership(party: Party, anonymousParty: AnonymousParty) {
        throw UnsupportedOperationException("not implemented")
    }

    override fun pathForAnonymous(anonymousParty: AnonymousParty): CertPath? {
        throw UnsupportedOperationException("not implemented")
    }

    override fun registerPath(party: Party, anonymousParty: AnonymousParty, path: CertPath) {
        var previousCertificate: X509Certificate? = null
        for (cert in path.certificates) {
            if (cert is X509Certificate) {
                if (previousCertificate == null) {
                    val expectedParty = cert.subjectX500Principal.toString()
                    require(expectedParty == party.name) { "First certificate subject must be the well known identity. Expected ${expectedParty} found ${party.name}" }
                } else {
                    require(cert.issuerX500Principal == previousCertificate.subjectX500Principal)
                    cert.verify(previousCertificate.publicKey)
                }
                previousCertificate = cert
            } else {
                throw IllegalArgumentException("Found non-X509 certificate in certificate path.")
            }
        }
        val expectedPartyKey = previousCertificate?.publicKey
        require(expectedPartyKey is CompositeKey
                && expectedPartyKey == anonymousParty.owningKey) { "Last certificate's subject must be anonymous party. Expected ${expectedPartyKey} found ${anonymousParty.owningKey.toStringShort()}" }

        partyToPath[anonymousParty] == path
    }
}
