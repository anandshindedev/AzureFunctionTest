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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.security.SecureRandom;
import java.util.*;

import static com.demo.SharedData.*;

public class GenerateDek {

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
            List<String> missingVarsList = dataValidation();
            if (!missingVarsList.isEmpty()) {
                String missingVars = String.join(", ", missingVarsList);

                return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Missing required environment variables: " + missingVars)
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
}
