package net.corda.core.node

data class VersionInfo(
        /**
         * Platform version of the node which is an integer value which increments on any release where any of the public
         * API of the entire Corda platform changes. This includes messaging, serialisation, node APIs, etc.
         */
        val platformVersion: Int,
        /** Release version string of the node which is typically in major.minor format. */
        val releaseVersion: String,
        /** The exact version control commit ID of the node build. */
        val revision: String,
        /** The node vendor */
        val vendor: String)