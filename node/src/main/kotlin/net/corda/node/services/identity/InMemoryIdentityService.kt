package net.corda.node.services.identity

import net.corda.core.contracts.PartyAndReference
import net.corda.core.crypto.AnonymousParty
import net.corda.core.crypto.Party
import net.corda.core.crypto.X509Utilities
import net.corda.core.node.services.IdentityService
import net.corda.core.serialization.SingletonSerializeAsToken
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.trace
import java.security.InvalidAlgorithmParameterException
import java.security.PublicKey
import java.security.cert.*
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.annotation.concurrent.ThreadSafe
import javax.security.auth.x500.X500Principal

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

    @Throws(CertificateExpiredException::class, CertificateNotYetValidException::class, InvalidAlgorithmParameterException::class)
    override fun registerPath(party: Party, anonymousParty: AnonymousParty, path: CertPath) {
        val expectedTrustAnchor = TrustAnchor(X509Utilities.getDevX509Name(party.name).toString(), party.owningKey, null)
        require(path.certificates.isNotEmpty()) { "Certificate path must contain at least one certificate" }
        val validator = CertPathValidator.getInstance("PKIX")
        val result = validator.validate(path, PKIXParameters(setOf(expectedTrustAnchor))) as PKIXCertPathValidatorResult
        require(result.trustAnchor.caName == party.name)
        require(result.publicKey == anonymousParty.owningKey)

        partyToPath[anonymousParty] == path
    }
}
