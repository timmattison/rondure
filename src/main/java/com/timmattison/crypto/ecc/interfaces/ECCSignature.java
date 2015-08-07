package com.timmattison.crypto.ecc.interfaces;

import java.math.BigInteger;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 5/21/13
 * Time: 7:22 AM
 * To change this template use File | Settings | File Templates.
 */
public interface ECCSignature {
    BigInteger getR();

    BigInteger getS();

    ECCParameters getECCParameters();

    BigInteger getN();

    ECCPoint getG();

    ECCPoint getQu();
}
