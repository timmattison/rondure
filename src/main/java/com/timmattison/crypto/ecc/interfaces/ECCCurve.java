package com.timmattison.crypto.ecc.interfaces;

import java.math.BigInteger;
import java.util.Random;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 5/20/13
 * Time: 7:08 AM
 * To change this template use File | Settings | File Templates.
 */
public interface ECCCurve extends ECCElement {
    // The formula used for ECC curves is:

    // E : y^2 = x^3 + a*x + b (mod p)

    /**
     * The modulus ("mod p" value of the equation)
     *
     * @return
     */
    BigInteger getP();

    /**
     * X is multiplied by this
     *
     * @return
     */
    ECCFieldElement getA();

    /**
     * This is the last value added in the equation
     *
     * @return
     */
    ECCFieldElement getB();

    /**
     * This is the order of the curve (the number of points on it including the identity point)
     *
     * @return
     */
    BigInteger getOrder();

    boolean equals(ECCCurve other);

    /**
     * Must be transient for serialization!
     *
     * @return
     */
    ECCPoint getInfinity();

    ECCPoint generateBasePoint(Random random);

    ECCFieldElement fromBigInteger(BigInteger x);

    // for now, work with hex strings because they're easier in JS
    ECCPoint decodePointHex(String s);

    ECCPoint decodePointBinary(byte[] point);
}
