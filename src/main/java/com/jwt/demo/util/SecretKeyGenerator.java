package com.jwt.demo.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class SecretKeyGenerator {
    public static void main(String[] args) throws Exception {
        String base = "seo sung-won";

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] hash = sha512.digest(base.getBytes(StandardCharsets.UTF_8));

        String base64EncodedSecret = Base64.getEncoder().encodeToString(hash);
        System.out.println("Base64 Secret: " + base64EncodedSecret);
    }
}
