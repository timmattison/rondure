package com.timmattison.crypto.ecc.hashing.sha;

import com.google.inject.assistedinject.Assisted;
import com.timmattison.crypto.ecc.helpers.ByteArrayHelper;
import com.timmattison.crypto.ecc.interfaces.Hash;

import javax.inject.Inject;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SingleSha1Hash implements Hash {
    private static final String SHA1_ALGORITHM = "SHA-1";
    private final byte[] input;
    private byte[] output;
    private BigInteger outputBigInteger;

    @Inject
    public SingleSha1Hash(@Assisted("input") byte[] input) {
        this.input = input;
    }

    @Override
    public byte[] getInput() {
        return input;
    }

    @Override
    public byte[] getOutput() {
        if (output == null) {
            try {
                MessageDigest messageDigest1 = MessageDigest.getInstance(SHA1_ALGORITHM);

                output = messageDigest1.digest(input);
            } catch (NoSuchAlgorithmException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        return output;
    }

    @Override
    public BigInteger getOutputBigInteger() {
        if (outputBigInteger == null) {
            outputBigInteger = new BigInteger(ByteArrayHelper.reverseBytes(getOutput()));
        }

        return outputBigInteger;
    }
}
