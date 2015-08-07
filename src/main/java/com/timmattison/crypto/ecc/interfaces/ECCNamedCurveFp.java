package com.timmattison.crypto.ecc.interfaces;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 5/20/13
 * Time: 8:23 AM
 * To change this template use File | Settings | File Templates.
 */
public interface ECCNamedCurveFp {
    ECCParameters getSecp128r1();

    ECCParameters getSecp160k1();

    ECCParameters getSecp160r1();

    ECCParameters getSecp192k1();

    ECCParameters getSecp192r1();

    ECCParameters getSecp224r1();

    ECCParameters getSecp256r1();

    ECCParameters getSecp256k1();
}
