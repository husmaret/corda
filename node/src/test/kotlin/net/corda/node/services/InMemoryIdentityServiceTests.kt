package net.corda.node.services

import net.corda.core.crypto.*
import net.corda.node.services.identity.InMemoryIdentityService
import net.corda.testing.ALICE
import net.corda.testing.ALICE_PUBKEY
import net.corda.testing.BOB
import net.corda.testing.BOB_PUBKEY
import org.junit.Test
import java.security.Security
import java.security.cert.CertPath
import java.security.cert.CertificateFactory
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
        System.setProperty("java.security.debug", "certpath")
        Security.addProvider(CompositeProvider())
        val service = InMemoryIdentityService()
        val identityCertAndKey = X509Utilities.createSelfSignedCACert("Node A")
        val identityKey = identityCertAndKey.keyPair
        val identityCertificate = identityCertAndKey.certificate
        val identity = Party("Node A", identityKey.public)

        val txCertAndKey = X509Utilities.createIntermediateCert("Node A", identityCertAndKey)
        val txIdentity = AnonymousParty(txCertAndKey.keyPair.public)
        val txCertificate = txCertAndKey.certificate

        val certPathFactory = CertificateFactory.getInstance("X.509")
        val txCertPath: CertPath = certPathFactory.generateCertPath(listOf(identityCertificate))
        service.registerPath(identity, txIdentity, txCertPath)
        service.assertOwnership(identity, txIdentity)
    }
}