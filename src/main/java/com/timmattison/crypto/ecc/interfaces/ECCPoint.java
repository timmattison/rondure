package com.timmattison.crypto.ecc.interfaces;

import java.math.BigInteger;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 5/20/13
 * Time: 6:56 AM
 * To change this template use File | Settings | File Templates.
 */
public interface ECCPoint extends ECCElement {
    ECCCurve getCurve();

    ECCFieldElement getX();

    ECCFieldElement getY();

    boolean equals(ECCPoint other);

    boolean isInfinity();

    ECCPoint negate();

    ECCPoint add(ECCPoint b);

    ECCPoint twice();

    ECCPoint multiply(BigInteger k);
}