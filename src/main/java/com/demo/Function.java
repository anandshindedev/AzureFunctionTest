package com.demo;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.WrapResult;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobContainerClientBuilder;
import com.azure.storage.blob.specialized.BlobLeaseClient;
import com.azure.storage.blob.specialized.BlobLeaseClientBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.EventGridTrigger;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Azure Functions with HTTP Trigger.
 */
public class Function {
    /**
     * This function listens at endpoint "/api/HttpExample". Two ways to invoke it using "curl" command in bash:
     * 1. curl -d "HTTP Body" {your host}/api/HttpExample
     * 2. curl "{your host}/api/HttpExample?name=HTTP%20Query"
     */

    private static final String KEY_VAULT_URL = System.getenv("KEY_VAULT_URL");
    private static final String KEK_NAME = System.getenv("KEK_NAME");
    private static final String MI_CLIENT_ID = System.getenv("UAMI_CLIENT_ID");
    private static final String SECRET_NAME = "wrapped-dek";
    private static final String STORAGE_CONNECTION_STRING = System.getenv("AzureWebJobsStorage");
    private static final String LOCK_CONTAINER = "locks";
    private static final String LOCK_BLOB = "dek-rotation-lock";
    private static final int LEASE_RETRY_COUNT = 5;
    private static final int LEASE_RETRY_DELAY_SEC = 5;
    private static final ObjectMapper mapper = new ObjectMapper();

    @FunctionName("generateDek")
    public HttpResponseMessage generateDek(
            @HttpTrigger(
                name = "req",
                methods = {HttpMethod.POST},
                authLevel = AuthorizationLevel.FUNCTION)
                HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {

        try {

            if (KEY_VAULT_URL == null || KEK_NAME == null || KEY_VAULT_URL.isBlank() || KEK_NAME.isBlank()) {
                return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Missing required environment variables: KEY_VAULT_URL or KEK_NAME")
                        .build();
            }

            context.getLogger().info("Azure Function: Generating DEK and wrapping with KEK...");

            // 1. Create a DEK (256 bits for AES-GCM)
            byte[] dek = new byte[32]; // 32 bytes = 256 bits
            new SecureRandom().nextBytes(dek);

            // 2. Setup Key and Secret clients
            var credential = new DefaultAzureCredentialBuilder()
                    .managedIdentityClientId(MI_CLIENT_ID)
                    .build();

            KeyClient keyClient = new KeyClientBuilder()
                    .vaultUrl(KEY_VAULT_URL)
                    .credential(credential)
                    .buildClient();

            KeyVaultKey key = keyClient.getKey(KEK_NAME);
            String keyIdWithVersion = key.getId();

            context.getLogger().info("Azure Function: keyIdWithVersion : " + keyIdWithVersion);

            CryptographyClient cryptoClient = new CryptographyClientBuilder()
                    .keyIdentifier(keyIdWithVersion)
                    .credential(credential)
                    .buildClient();

            SecretClient secretClient = new SecretClientBuilder()
                    .vaultUrl(KEY_VAULT_URL)
                    .credential(credential)
                    .buildClient();

            context.getLogger().info("Azure Function: credentials created");

            // 3. Wrap DEK using KEK
            WrapResult wrapResult = cryptoClient.wrapKey(KeyWrapAlgorithm.RSA_OAEP_256, dek);
            String wrappedDekBase64 = Base64.getEncoder().encodeToString(wrapResult.getEncryptedKey());

            context.getLogger().info("Azure Function: key wrapped");

            // 4. Build payload
            Map<String, Object> payload = new HashMap<>();
            payload.put("wrappedDek", wrappedDekBase64);
            payload.put("kekId", wrapResult.getKeyId());

            String payloadJson = mapper.writeValueAsString(payload);

            secretClient.setSecret(SECRET_NAME, payloadJson);

            context.getLogger().info("Payload stored in Key Vault secret: " + SECRET_NAME);

            // 6. Return payload
            return request.createResponseBuilder(HttpStatus.OK)
                    .body(Map.of(
                            "message", "DEK wrapped and stored successfully",
                            "secretName", SECRET_NAME,
                            "payload", payload))
                    .build();

        } catch (Exception e) {
            context.getLogger().severe("Error: " + e.getMessage());
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage())
                    .build();
        }

    }

    @FunctionName("kekRotationDekRewrap")
    public void kekRotationDekRewrap(@EventGridTrigger(name = "event") String eventJson, final ExecutionContext context) {
        try {

            JsonNode root = mapper.readTree(eventJson);
            context.getLogger().info("Received Event Data: " + root);
            String eventType = root.path("eventType").asText();

            context.getLogger().info("Received Event Type: " + eventType);
            if (!"Microsoft.KeyVault.KeyNewVersionCreated".equals(eventType)) {
                context.getLogger().info("Ignoring non-KeyNewVersionCreated event");
                return;
            }

            String latestKekId = root.path("data").path("Id").asText();
            context.getLogger().info("Latest KEK ID: " + latestKekId);

            var credential = new DefaultAzureCredentialBuilder()
                    .managedIdentityClientId(MI_CLIENT_ID)
                    .build();

            // Setup KeyVault clients
            SecretClient secretClient = new SecretClientBuilder().vaultUrl(KEY_VAULT_URL).credential(credential).buildClient();

            // Acquire blob lease for distributed locking
            BlobContainerClient containerClient = new BlobContainerClientBuilder()
                    .connectionString(STORAGE_CONNECTION_STRING)
                    .containerName(LOCK_CONTAINER)
                    .buildClient();
            BlobClient blobClient = containerClient.getBlobClient(LOCK_BLOB);
            BlobLeaseClient leaseClient = new BlobLeaseClientBuilder().blobClient(blobClient).buildClient();

            boolean leaseAcquired = false;
            for (int i = 0; i < LEASE_RETRY_COUNT; i++) {
                try {
                    leaseClient.acquireLease(60); // 60 seconds lease
                    leaseAcquired = true;
                    context.getLogger().info("Lease acquired");
                    break;
                } catch (Exception e) {
                    context.getLogger().warning("Lease acquisition failed, retrying in " + LEASE_RETRY_DELAY_SEC + "s...");
                    Thread.sleep(LEASE_RETRY_DELAY_SEC * 1000L);
                }
            }

            if (!leaseAcquired) {
                context.getLogger().info("Could not acquire lease, another instance may be processing. Exiting.");
                return;
            }

            try {
                // Fetch current DEK payload
                KeyVaultSecret secret = secretClient.getSecret(SECRET_NAME);
                JsonNode payload = mapper.readTree(secret.getValue());
                String oldWrappedDekBase64 = payload.path("wrappedDek").asText();
                String oldKekId = payload.path("kekId").asText();

                if (oldKekId.equalsIgnoreCase(latestKekId)) {
                    context.getLogger().info("Wrapped DEK already using latest KEK, nothing to do.");
                    return;
                }

                // Unwrap with old KEK
                CryptographyClient oldCrypto = new CryptographyClientBuilder()
                        .keyIdentifier(oldKekId)
                        .credential(credential)
                        .buildClient();
                byte[] dek = oldCrypto.unwrapKey(KeyWrapAlgorithm.RSA_OAEP_256, Base64.getDecoder().decode(oldWrappedDekBase64)).getKey();

                // Wrap with latest KEK
                CryptographyClient latestCrypto = new CryptographyClientBuilder()
                        .keyIdentifier(latestKekId)
                        .credential(credential)
                        .buildClient();
                WrapResult wrapResult = latestCrypto.wrapKey(KeyWrapAlgorithm.RSA_OAEP_256, dek);

                String newWrappedDekBase64 = Base64.getEncoder().encodeToString(wrapResult.getEncryptedKey());

                // Update Key Vault secret
                Map<String, String> newPayload = Map.of(
                        "wrappedDek", newWrappedDekBase64,
                        "kekId", latestKekId
                );
                secretClient.setSecret(SECRET_NAME, mapper.writeValueAsString(newPayload));

                context.getLogger().info("Wrapped DEK rewrapped successfully with latest KEK");

            } finally {
                leaseClient.releaseLease();
                context.getLogger().info("Lease released on blob");
            }

        } catch (Exception e) {
            context.getLogger().severe("Error during DEK rewrap: " + e.getMessage());
        }
    }
}
