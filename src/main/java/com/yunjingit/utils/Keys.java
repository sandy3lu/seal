package com.yunjingit.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class Keys {

    /**
     * Create a random keysize(i.e. 2048) bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair(int keysize)
            throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(keysize, new SecureRandom());

        return kpGen.generateKeyPair();
    }




}
