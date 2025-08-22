package com.demo;

import com.azure.core.util.BinaryData;
import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.specialized.BlockBlobClient;
import com.microsoft.azure.functions.*;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.util.Optional;

import static com.demo.SharedData.*;

public class UploadBlob {

    @FunctionName("uploadEmptyBlob")
    public HttpResponseMessage uploadEmptyBlob(
            @HttpTrigger(name = "req",
                    methods = {HttpMethod.POST},
                    authLevel = AuthorizationLevel.FUNCTION) // optional blobName as route param
            HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {

        context.getLogger().info("UploadEmptyBlobFunction invoked.");

        // Read required settings
        String endpoint = STORAGE_URL;
        String containerName = LOCK_CONTAINER;

        if (endpoint == null || endpoint.isEmpty()) {
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Missing environment variable: " + STORAGE_URL)
                    .build();
        }
        if (containerName == null || containerName.isEmpty()) {
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Missing environment variable: " + LOCK_CONTAINER)
                    .build();
        }

        // Determine blob name: route param > request body > timestamp-based default
        String blobName = "routeBlobName";

        try {
            // Create DefaultAzureCredential which will use the Managed Identity when running in Azure.
            DefaultAzureCredential credential = new DefaultAzureCredentialBuilder().managedIdentityClientId(MI_CLIENT_ID).build();

            // Build service client with the storage account blob endpoint and credential
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
                    .endpoint(endpoint) // e.g. https://<mystorageaccount>.blob.core.windows.net
                    .credential(credential)
                    .buildClient();

            // Get container client (container should already exist - optionally create if you want)
            BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient(containerName);


            BlockBlobClient blockBlobClient = containerClient.getBlobClient(blobName).getBlockBlobClient();

            // Upload an empty blob (0 bytes). BinaryData.fromBytes(new byte[0]) creates an empty payload.
            blockBlobClient.upload(BinaryData.fromBytes(new byte[0]), true);

            String msg = String.format("Uploaded empty blob '%s' to container '%s'.", blobName, containerName);
            context.getLogger().info(msg);

            return request.createResponseBuilder(HttpStatus.OK)
                    .body(msg)
                    .build();

        } catch (Exception ex) {
            context.getLogger().severe("Failed to upload empty blob: " + ex.getMessage());
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error uploading empty blob: " + ex.getMessage())
                    .build();
        }
    }
}
