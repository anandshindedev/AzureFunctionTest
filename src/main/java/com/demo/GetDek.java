package com.demo;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.azure.functions.*;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.util.*;

import static com.demo.SharedData.*;
import static com.demo.SharedData.KEY_VAULT_URL;
import static com.demo.SharedData.SECRET_NAME;

public class GetDek {

    private static final ObjectMapper mapper = new ObjectMapper();

    @FunctionName("getDek")
    public HttpResponseMessage getDek(
            @HttpTrigger(
                    name = "req",
                    methods = {HttpMethod.GET},
                    authLevel = AuthorizationLevel.FUNCTION)
            HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {

        try {

            var credential = new DefaultAzureCredentialBuilder()
                    .managedIdentityClientId(MI_CLIENT_ID)
                    .build();

            // Setup KeyVault clients
            SecretClient secretClient = new SecretClientBuilder().vaultUrl(KEY_VAULT_URL).credential(credential).buildClient();

            KeyVaultSecret secret = secretClient.getSecret(SECRET_NAME);
            JsonNode payload = mapper.readTree(secret.getValue());
            String wrappedDekBase64 = payload.path("wrappedDek").asText();
            String kekId = payload.path("kekId").asText();

            String shouldYouBeGettingThisKey = request.getQueryParameters().getOrDefault("shouldYouBeGettingThisKey", "");
            boolean pass = shouldYouBeGettingThisKey.equals("Yes");
            if(!pass) {
                return request.createResponseBuilder(HttpStatus.OK)
                        .body(Map.of(
                                "message", "DEK retrieved successfully",
                                "dek: ", wrappedDekBase64,
                                "kekId", kekId))
                        .build();
            }

            CryptographyClient oldCrypto = new CryptographyClientBuilder()
                    .keyIdentifier(kekId)
                    .credential(credential)
                    .buildClient();
            byte[] dek = oldCrypto.unwrapKey(KeyWrapAlgorithm.RSA_OAEP_256, Base64.getDecoder().decode(wrappedDekBase64)).getKey();

            return request.createResponseBuilder(HttpStatus.OK)
                    .body(Map.of(
                            "message", "DEK retrieved successfully",
                            "java.util.Base64.getEncoder().encodeToString(dek) dek: ", Base64.getEncoder().encodeToString(dek),
                            "kekId", kekId))
                    .build();

        } catch (Exception e) {
            context.getLogger().severe("Error: " + e.getMessage());
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage())
                    .build();
        }
    }

}
