package com.demo;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.WrapResult;
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
import com.microsoft.azure.functions.annotation.EventGridTrigger;
import com.microsoft.azure.functions.annotation.FunctionName;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static com.demo.SharedData.*;

public class KekRotationDekRewrap {

    private static final ObjectMapper mapper = new ObjectMapper();

    @FunctionName("kekRotationDekRewrap")
    public void kekRotationDekRewrap(@EventGridTrigger(name = "event") String eventJson, final ExecutionContext context) {
        try {

            List<String> missingVarsList = dataValidation();
            if (!missingVarsList.isEmpty()) {
                String missingVars = String.join(", ", missingVarsList);
                context.getLogger().severe("Missing required environment variables: " + missingVars);
                return;
            }

            JsonNode root = mapper.readTree(eventJson);
            context.getLogger().info("Received Event Data: " + root);
            String eventType = root.path("eventType").asText();

            context.getLogger().info("Received Event Type: " + eventType);
            if (!"Microsoft.KeyVault.KeyNewVersionCreated".equals(eventType)) {
                context.getLogger().severe("Ignoring non-KeyNewVersionCreated event");
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
