package com.timmattison.crypto.ecc.interfaces;

import java.math.BigInteger;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 5/20/13
 * Time: 6:48 AM
 * To change this template use File | Settings | File Templates.
 */
public interface ECCFieldElement extends ECCElement {
    /**
     * The modulus of the curve that this field element is used on
     *
     * @return
     */
    BigInteger getQ();

    /**
     * The value of this field element
     *
     * @return
     */
    BigInteger getX();

    boolean equals(ECCFieldElement other);

    BigInteger toBigInteger();

    /**
     * Must be transient for serialization!
     *
     * @return
     */
    ECCFieldElement negate();

    ECCFieldElement add(ECCFieldElement b);

    ECCFieldElement subtract(ECCFieldElement b);

    ECCFieldElement multiply(ECCFieldElement b);

    /**
     * Must be transient for serialization!
     *
     * @return
     */
    ECCFieldElement square();

    ECCFieldElement divide(ECCFieldElement b);
}
