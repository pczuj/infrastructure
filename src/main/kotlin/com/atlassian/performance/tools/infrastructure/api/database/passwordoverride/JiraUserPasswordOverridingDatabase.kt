package com.atlassian.performance.tools.infrastructure.api.database.passwordoverride

import com.atlassian.performance.tools.infrastructure.api.database.Database
import com.atlassian.performance.tools.infrastructure.database.SshMysqlClient
import com.atlassian.performance.tools.infrastructure.database.SshSqlClient
import com.atlassian.performance.tools.ssh.api.SshConnection
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.net.URI
import java.util.function.Function

class JiraUserPasswordOverridingDatabase private constructor(
    private val databaseDelegate: Database,
    private val username: String,
    private val plainTextPassword: String,
    private val passwordEncryption: Function<String, String>,
    private val sqlClient: SshSqlClient,
    private val schema: String
) : Database {
    private val logger: Logger = LogManager.getLogger(this::class.java)

    override fun setup(ssh: SshConnection): String = databaseDelegate.setup(ssh)

    override fun start(
        jira: URI,
        ssh: SshConnection
    ) {
        databaseDelegate.start(jira, ssh)
        val methodSelect = "SELECT attribute_value FROM $schema.cwd_directory_attribute" +
            " WHERE attribute_name = 'user_encryption_method';"
        val encryptionMethod = sqlClient.runSql(ssh, methodSelect).output
        val password = when {
            encryptionMethod.contains("plaintext") -> plainTextPassword
            encryptionMethod.contains("atlassian-security") -> passwordEncryption.apply(plainTextPassword)
            else -> throw RuntimeException("Unknown jira user password encryption type")
        }
        val passwordUpdate = "UPDATE $schema.cwd_user SET credential='$password'" +
            " WHERE user_name='$username';"
        sqlClient.runSql(ssh, passwordUpdate)
        logger.debug("Password for user '$username' updated to '$plainTextPassword'")
    }

    class Builder(
        private var databaseDelegate: Database,
        private var passwordEncryption: Function<String, String>
    ) {
        private var sqlClient: SshSqlClient = SshMysqlClient()
        private var schema: String = "jiradb"
        private var username: String = "admin"
        private var plainTextPassword: String = "admin"

        fun databaseDelegate(databaseDelegate: Database) = apply { this.databaseDelegate = databaseDelegate }
        fun username(username: String) = apply { this.username = username }
        fun plainTextPassword(passwordPlainText: String) = apply { this.plainTextPassword = passwordPlainText }
        fun sqlClient(sqlClient: SshSqlClient) = apply { this.sqlClient = sqlClient }
        fun schema(jiraDatabaseSchemaName: String) = apply { this.schema = jiraDatabaseSchemaName }
        fun passwordEncryption(passwordEncryption: Function<String, String>) =
            apply { this.passwordEncryption = passwordEncryption }

        fun build() = JiraUserPasswordOverridingDatabase(
            databaseDelegate = databaseDelegate,
            sqlClient = sqlClient,
            username = username,
            plainTextPassword = plainTextPassword,
            passwordEncryption = passwordEncryption,
            schema = schema
        )
    }

}

/**
 * @param passwordEncryption Based on [retrieving-the-jira-administrator](https://confluence.atlassian.com/jira/retrieving-the-jira-administrator-192836.html)
 * to encode the password in Jira format use [com.atlassian.crowd.password.encoder.AtlassianSecurityPasswordEncoder](https://docs.atlassian.com/atlassian-crowd/4.2.2/com/atlassian/crowd/password/encoder/AtlassianSecurityPasswordEncoder.html)
 * from the [com.atlassian.crowd.crowd-password-encoders](https://mvnrepository.com/artifact/com.atlassian.crowd/crowd-password-encoders/4.2.2).
 */
fun Database.overridePassword(
    passwordEncryption: Function<String, String>
): JiraUserPasswordOverridingDatabase.Builder = JiraUserPasswordOverridingDatabase.Builder(
    databaseDelegate = this,
    passwordEncryption = passwordEncryption
)