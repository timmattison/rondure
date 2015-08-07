package com.timmattison.crypto.ecc.random.impl;

import com.timmattison.crypto.ecc.random.interfaces.RandomFactory;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Created by timmattison on 8/7/15.
 */
public class SecureRandomFactory implements RandomFactory {
    @Override
    public Random create() {
        return new SecureRandom();
    }
}
