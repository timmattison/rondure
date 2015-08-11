package com.timmattison.crypto.ecc.interfaces;

import com.google.inject.assistedinject.Assisted;

import java.math.BigInteger;

/**
 * Created with IntelliJ IDEA.
 * User: Tim
 * Date: 8/22/13
 * Time: 7:20 AM
 * To change this template use File | Settings | File Templates.
 */
public interface ECCKeyPairFactory {
    ECCKeyPair create(@Assisted("eccParameters") ECCParameters eccParameters, @Assisted("dU") BigInteger dU);
}
