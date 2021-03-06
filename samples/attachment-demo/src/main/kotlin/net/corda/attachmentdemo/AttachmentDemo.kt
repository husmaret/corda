package net.corda.attachmentdemo

import com.google.common.net.HostAndPort
import joptsimple.OptionParser
import net.corda.client.rpc.CordaRPCClient
import net.corda.core.contracts.TransactionType
import net.corda.core.crypto.Party
import net.corda.core.crypto.SecureHash
import net.corda.core.div
import net.corda.core.getOrThrow
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.startFlow
import net.corda.core.sizedInputStreamAndHash
import net.corda.core.utilities.ALICE_KEY
import net.corda.core.utilities.Emoji
import net.corda.flows.FinalityFlow
import net.corda.nodeapi.config.SSLConfiguration
import java.io.InputStream
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.system.exitProcess
import kotlin.test.assertEquals

internal enum class Role {
    SENDER,
    RECIPIENT
}

fun main(args: Array<String>) {
    val parser = OptionParser()

    val roleArg = parser.accepts("role").withRequiredArg().ofType(Role::class.java).required()
    val options = try {
        parser.parse(*args)
    } catch (e: Exception) {
        println(e.message)
        printHelp(parser)
        exitProcess(1)
    }

    val role = options.valueOf(roleArg)!!
    when (role) {
        Role.SENDER -> {
            val host = HostAndPort.fromString("localhost:10006")
            println("Connecting to sender node ($host)")
            CordaRPCClient(host).use("demo", "demo") {
                sender(this)
            }
        }
        Role.RECIPIENT -> {
            val host = HostAndPort.fromString("localhost:10009")
            println("Connecting to the recipient node ($host)")
            CordaRPCClient(host).use("demo", "demo") {
                recipient(this)
            }
        }
    }
}

var EXPECTED_HASH = SecureHash.zeroHash // Note: We could use another random default value to initialize it.

/** An in memory test zip attachment of at least numOfClearBytes size, will be used. */
fun sender(rpc: CordaRPCOps, numOfClearBytes: Int = 1024) { // default size 1K.
    val (inputStream, hash) = sizedInputStreamAndHash(numOfClearBytes)
    sender(rpc, inputStream, hash)
}

fun sender(rpc: CordaRPCOps, inputStream: InputStream, hash: SecureHash.SHA256) {
    EXPECTED_HASH = hash
    // Get the identity key of the other side (the recipient).
    val otherSide: Party = rpc.partyFromName("Bank B")!!

    // Make sure we have the file in storage
    if (!rpc.attachmentExists(hash)) {
        inputStream.use {
            val id = rpc.uploadAttachment(it)
            assertEquals(hash, id)
        }
    }

    // Create a trivial transaction that just passes across the attachment - in normal cases there would be
    // inputs, outputs and commands that refer to this attachment.
    val ptx = TransactionType.General.Builder(notary = null)
    require(rpc.attachmentExists(hash))
    ptx.addAttachment(hash)
    // TODO: Add a dummy state and specify a notary, so that the tx hash is randomised each time and the demo can be repeated.

    // Despite not having any states, we have to have at least one signature on the transaction
    ptx.signWith(ALICE_KEY)

    // Send the transaction to the other recipient
    val stx = ptx.toSignedTransaction()
    println("Sending ${stx.id}")
    val flowHandle = rpc.startFlow(::FinalityFlow, stx, setOf(otherSide))
    flowHandle.progress.subscribe(::println)
    flowHandle.returnValue.getOrThrow()
}

fun recipient(rpc: CordaRPCOps) {
    println("Waiting to receive transaction ...")
    val stx = rpc.verifiedTransactions().second.toBlocking().first()
    val wtx = stx.tx
    if (wtx.attachments.isNotEmpty()) {
        assertEquals(EXPECTED_HASH, wtx.attachments.first())
        require(rpc.attachmentExists(EXPECTED_HASH))
        println("File received - we're happy!\n\nFinal transaction is:\n\n${Emoji.renderIfSupported(wtx)}")
    } else {
        println("Error: no attachments found in ${wtx.id}")
    }
}

private fun printHelp(parser: OptionParser) {
    println("""
    Usage: attachment-demo --role [RECIPIENT|SENDER] [options]
    Please refer to the documentation in docs/build/index.html for more info.

    """.trimIndent())
    parser.printHelpOn(System.out)
}

// TODO: Take this out once we have a dedicated RPC port and allow SSL on it to be optional.
private fun sslConfigFor(nodename: String, certsPath: String?): SSLConfiguration {
    return object : SSLConfiguration {
        override val keyStorePassword: String = "cordacadevpass"
        override val trustStorePassword: String = "trustpass"
        override val certificatesDirectory: Path = if (certsPath != null) Paths.get(certsPath) else Paths.get("build") / "nodes" / nodename / "certificates"
    }
}
