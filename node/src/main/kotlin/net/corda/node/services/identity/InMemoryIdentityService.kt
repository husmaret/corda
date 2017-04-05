package net.corda.node.services.identity

import net.corda.core.contracts.PartyAndReference
import net.corda.core.crypto.AnonymousParty
import net.corda.core.crypto.EdDSAKeyFactory
import net.corda.core.crypto.Party
import net.corda.core.crypto.toStringShort
import net.corda.core.node.services.IdentityService
import net.corda.core.serialization.SingletonSerializeAsToken
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.trace
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.path.CertPath
import sun.security.x509.SubjectKeyIdentifierExtension
import java.security.PublicKey
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
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

    @Throws(CertificateExpiredException::class, CertificateNotYetValidException::class)
    override fun registerPath(party: Party, anonymousParty: AnonymousParty, path: CertPath) {
        val now = Date()
        var previousCertificate: X509CertificateHolder? = null
        for (cert in path.certificates) {
            require(cert.subjectPublicKeyInfo != null) { "Certificate must include a public key" }
            require(cert.isValidOn(now)) { "Certificate must be valid at the current time" }
            if (previousCertificate == null) {
                require(cert.subject == X500Name(party.name)) { "First certificate subject must be the well known identity. Expected ${cert.subject} found ${party.name}" }
            } else {
                require(cert.issuer == previousCertificate.subject)
                // FIXME: require(cert.isSignatureValid(previousCertificate.subjectPublicKeyInfo))
            }
            previousCertificate = cert
        }
        val expectedPartyKey = previousCertificate?.subjectPublicKeyInfo?.publicKeyData
        require(Arrays.equals(expectedPartyKey?.bytes, anonymousParty.owningKey.encoded)) { "Last certificate's subject must be anonymous party." }

        partyToPath[anonymousParty] == path
    }
}
