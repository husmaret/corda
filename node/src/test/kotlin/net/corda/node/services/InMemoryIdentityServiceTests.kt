package net.corda.node.services

import net.corda.core.crypto.*
import net.corda.core.serialization.serialize
import net.corda.node.services.identity.InMemoryIdentityService
import net.corda.testing.ALICE
import net.corda.testing.ALICE_PUBKEY
import net.corda.testing.BOB
import net.corda.testing.BOB_PUBKEY
import net.i2p.crypto.eddsa.EdDSAEngine
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.ContentSigner
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.PublicKey
import java.security.Security
import java.security.cert.CertPath
import java.security.cert.CertificateFactory
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Tests for the in memory identity service.
 */
class InMemoryIdentityServiceTests {
    @Test
    fun `get all identities`() {
        val service = InMemoryIdentityService()
        assertNull(service.getAllIdentities().firstOrNull())
        service.registerIdentity(ALICE)
        var expected = setOf(ALICE)
        var actual = service.getAllIdentities().toHashSet()
        assertEquals(expected, actual)

        // Add a second party and check we get both back
        service.registerIdentity(BOB)
        expected = setOf(ALICE, BOB)
        actual = service.getAllIdentities().toHashSet()
        assertEquals(expected, actual)
    }

    @Test
    fun `get identity by key`() {
        val service = InMemoryIdentityService()
        assertNull(service.partyFromKey(ALICE_PUBKEY))
        service.registerIdentity(ALICE)
        assertEquals(ALICE, service.partyFromKey(ALICE_PUBKEY))
        assertNull(service.partyFromKey(BOB_PUBKEY))
    }

    @Test
    fun `get identity by name with no registered identities`() {
        val service = InMemoryIdentityService()
        assertNull(service.partyFromName(ALICE.name))
    }

    @Test
    fun `get identity by name`() {
        val service = InMemoryIdentityService()
        val identities = listOf("Node A", "Node B", "Node C").map { Party(it, generateKeyPair().public) }
        assertNull(service.partyFromName(identities.first().name))
        identities.forEach { service.registerIdentity(it) }
        identities.forEach { assertEquals(it, service.partyFromName(it.name)) }
    }

    @Test
    fun `assert anonymous key owned by identity`() {
        Security.addProvider(CompositeProvider())
        val caName = X500Name("cn=Node A")
        val service = InMemoryIdentityService()
        val identityKey = generateKeyPair()
        val identity = Party(caName.toString(), identityKey.public)
        val issuer = caName
        val serial = BigInteger.ONE
        val notBefore = Date()
        val notAfter = Date(notBefore.getTime() + 24 * 60 * 60 * 1000L)
        val identityCertificate = buildCertificate(identityKey, identity.owningKey, issuer, notAfter, notBefore, serial, issuer)

        val txIdentity = AnonymousParty(generateKeyPair().public)
        val txCertificate = buildCertificate(identityKey, identity.owningKey, issuer, notAfter, notBefore, serial, caName)

        val certFactory = CertificateFactory.getInstance("X.509")
        val certificateConverter = JcaX509CertificateConverter().setProvider("BC")
        val certList = listOf(identityCertificate, txCertificate).map { certificateConverter.getCertificate(it) }
        val txCertPath: CertPath = certFactory.generateCertPath(certList)
        service.registerPath(identity, txIdentity, txCertPath)
        service.assertOwnership(identity, txIdentity)
    }

    private fun buildCertificate(signingKey: KeyPair, issuerKey: PublicKey, issuer: X500Name, notAfter: Date, notBefore: Date, serial: BigInteger?, subject: X500Name):X509CertificateHolder {
        val publicKeyInfo = SubjectPublicKeyInfo(CompositeProvider.EDDSA_ALG_IDENTIFIER, issuerKey.encoded)
        val certBuilder = X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKeyInfo)
        val signer = Signer(signingKey)
        return certBuilder.build(signer)
    }

    class Signer(val identityKey: KeyPair): ContentSigner {
        private val stream = ByteArrayOutputStream()
        override fun getAlgorithmIdentifier(): AlgorithmIdentifier = CompositeProvider.EDDSA_ALG_IDENTIFIER
        override fun getOutputStream(): OutputStream = stream
        override fun getSignature(): ByteArray {
            val engine = EdDSAEngine()
            engine.initSign(identityKey.private)
            engine.update(stream.toByteArray())
            val signatureBytes = engine.sign()
            val signature = DigitalSignature.WithKey(identityKey.public, signatureBytes)
            return signature.serialize().bytes
        }
    }
}