package com.timmattison.crypto.ecc.helpers;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 4/12/13
 * Time: 11:07 AM
 * To change this template use File | Settings | File Templates.
 */
public class ByteArrayHelper {
    /**
     * Reverse a byte array.  Typically used when endianness is backwards and we're converting to BigIntegers.
     *
     * @param input
     * @return
     */
    public static byte[] reverseBytes(byte[] input) {
        if (input == null) {
            throw new UnsupportedOperationException("Input cannot be NULL");
        }

        byte[] returnValue = new byte[input.length];

        for (int loop = 0; loop < input.length; loop++) {
            returnValue[loop] = input[input.length - loop - 1];
        }

        return returnValue;
    }

    public static String toHex(byte[] input) {
        StringBuilder stringBuilder = new StringBuilder();

        for (byte value : input) {
            stringBuilder.append(String.format("%02x", value));
        }

        return stringBuilder.toString();
    }
}
