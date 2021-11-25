package com.atlassian.performance.tools.infrastructure.api.database

import com.atlassian.performance.tools.infrastructure.database.SshSqlClient
import com.atlassian.performance.tools.ssh.api.SshConnection
import java.net.URI

/**
 * Highest level class which defines the whole behavior.
 * You should know what the whole behavior is just by looking at the names.
 * If there would be something higher than the default implementations could be passed further.
 */
class JiraDatabaseReconfigurator(
    private val sshSqlClient: SshSqlClient
) {
    fun changeUserPassword(
        database: Database,
        username: String,
        newPassword: String
    ) = PasswordOverridingDatabase(
        delegate = database,
        username = username,
        newPassword = newPassword,
        sshConnectingPasswordEncryptor = { sshConnection ->
            MethodBasedPasswordEncoder(
                userEncryptionMethodResolver = JiraUserEncryptionMethodResolver(
                    attributeResolver = JiraDirectoryAttributeResolver(
                        sqlClient = SshConnectedSqlClient(
                            sqlClient = sshSqlClient,
                            sshConnection = sshConnection
                        )
                    )
                ),
                userEncryptionMethods = mapOf(
                    "atlassian-security" to AtlassianSecurityPasswordEncrypter(),
                    "plaintext" to { password: String -> password }
                )
            )
        },
        sshConnectingJiraUserPasswordOverrider = { sshConnection ->
            JiraUserPasswordOverrider(
                sqlClient = SshConnectedSqlClient(
                    sqlClient = sshSqlClient,
                    sshConnection = sshConnection
                )
            )
        }
    )
}

/**
 * Some classes below could be `internal`
 */

class PasswordOverridingDatabase(
    private val delegate: Database,
    private val username: String,
    private val newPassword: String,
    private val sshConnectingPasswordEncryptor: (SshConnection) -> ((password: String) -> String),
    private val sshConnectingJiraUserPasswordOverrider: (SshConnection) -> ((username: String, newPassword: String) -> Unit)
) : Database {
    override fun setup(ssh: SshConnection) = delegate.setup(ssh)

    override fun start(jira: URI, ssh: SshConnection) {
        delegate.start(jira, ssh)
        val passwordOverrider = sshConnectingJiraUserPasswordOverrider(ssh)
        val passwordEncoder = sshConnectingPasswordEncryptor(ssh)
        passwordOverrider(username, passwordEncoder(newPassword))
    }
}

class MethodBasedPasswordEncoder(
    private val userEncryptionMethodResolver: () -> String,
    private val userEncryptionMethods: Map<String, (String) -> String>,
    private val defaultEncryptionMethod: (String) -> String = { it }
): (String) -> String {
    override fun invoke(password: String) = userEncryptionMethods[userEncryptionMethodResolver()]
        ?.let { it(password) }
        ?: defaultEncryptionMethod(password)
}

class JiraUserEncryptionMethodResolver(
    private val attributeResolver: (String) -> String,
    private val userEncryptionMethodAttributeName: String = "user_encryption_method"
): () -> String {
    override fun invoke() = attributeResolver(userEncryptionMethodAttributeName)
}

class JiraDirectoryAttributeResolver(
    private val sqlClient: (String) -> String,
    private val directoryAttributeTableName: String = "jiradb.cwd_directory_attribute"
): (String) -> String {
    override fun invoke(attributeName: String) = sqlClient(
        "select attribute_value from $directoryAttributeTableName where attribute_name = '$attributeName';"
    )
}

class SshConnectedSqlClient(
    private val sqlClient: SshSqlClient,
    private val sshConnection: SshConnection
): (String) -> String {
    override fun invoke(sql: String) = sqlClient.runSql(sshConnection, sql).output
}

class AtlassianSecurityPasswordEncrypter : (String) -> String {
    override fun invoke(password: String) = "..."
}

/**
 * Based on https://confluence.atlassian.com/jira/retrieving-the-jira-administrator-192836.html
 */
class JiraUserPasswordOverrider(
    private val sqlClient: (String) -> String,
    private val userTableName: String = "jiradb.cwd_user"
): (String, String) -> Unit {
    override fun invoke(
        username: String,
        password: String
    ) = sqlClient("UPDATE $userTableName SET credential='$password' WHERE user_name='$username';").let { }
}