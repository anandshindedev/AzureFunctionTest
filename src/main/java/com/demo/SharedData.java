package com.demo;

import java.util.ArrayList;
import java.util.List;

public class SharedData {
    public static final String KEY_VAULT_URL = System.getenv("KEY_VAULT_URL");
    public static final String KEK_NAME = System.getenv("KEK_NAME");
    public static final String MI_CLIENT_ID = System.getenv("UAMI_CLIENT_ID");
    public static final String SECRET_NAME = System.getenv("SECRET_NAME");
    public static final String STORAGE_CONNECTION_STRING = System.getenv("AzureWebJobsStorage");
    public static final String STORAGE_URL = System.getenv("STORAGE_URL");
    public static final String LOCK_CONTAINER = System.getenv("LOCK_CONTAINER");
    public static final String LOCK_BLOB = System.getenv("LOCK_BLOB");
    public static final int LEASE_RETRY_COUNT = 3;
    public static final int LEASE_RETRY_DELAY_SEC = 3;

    public static List<String> dataValidation() {
        List<String> missing = new ArrayList<>();

        if (KEY_VAULT_URL == null || KEY_VAULT_URL.isBlank()) {
            missing.add("KEY_VAULT_URL");
        }
        if (KEK_NAME == null || KEK_NAME.isBlank()) {
            missing.add("KEK_NAME");
        }
        if (MI_CLIENT_ID == null || MI_CLIENT_ID.isBlank()) {
            missing.add("UAMI_CLIENT_ID");
        }
        if (SECRET_NAME == null || SECRET_NAME.isBlank()) {
            missing.add("SECRET_NAME");
        }
        if (STORAGE_CONNECTION_STRING == null || STORAGE_CONNECTION_STRING.isBlank()) {
            missing.add("AzureWebJobsStorage");
        }
        if (LOCK_CONTAINER == null || LOCK_CONTAINER.isBlank()) {
            missing.add("LOCK_CONTAINER");
        }
        if (LOCK_BLOB == null || LOCK_BLOB.isBlank()) {
            missing.add("LOCK_BLOB");
        }
        if (STORAGE_URL == null || STORAGE_URL.isBlank()) {
            missing.add("STORAGE_URL");
        }

        return missing;
    }
}
