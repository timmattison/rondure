package com.timmattison.crypto.ecc.interfaces;

import java.math.BigInteger;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 5/20/13
 * Time: 7:24 PM
 * To change this template use File | Settings | File Templates.
 */
public interface ECCKeyPair extends ECCElement {
    /**
     * The private key.  Must be in the interval [1, n-1] (notation indicates inclusive of 1 and n-1)
     *
     * @return
     */
    BigInteger getD();

    /**
     * The public key
     *
     * @return
     */
    ECCPoint getQ();

    /**
     * The N value for the curve parameters used with this key
     *
     * @return
     */
    BigInteger getN();

    /**
     * The G value for the curve parameters used with this key
     *
     * @return
     */
    ECCPoint getG();

    /**
     * A convenience method to get the x9EC parameters for the curve used with this key
     *
     * @return
     */
    ECCParameters getECCParameters();
}
