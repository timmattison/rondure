package com.timmattison.crypto.modules;

import com.google.inject.AbstractModule;
import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.timmattison.crypto.ecc.fp.*;
import com.timmattison.crypto.ecc.interfaces.*;
import com.timmattison.crypto.ecc.random.impl.RealBigIntegerRandom;
import com.timmattison.crypto.ecc.random.interfaces.BigIntegerRandom;
import com.timmattison.crypto.ecc.random.interfaces.RandomFactory;
import com.timmattison.crypto.ecc.interfaces.Hash;
import com.timmattison.crypto.ecc.hashing.sha.SingleSha1Hash;

import java.util.Random;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 7/31/13
 * Time: 5:56 PM
 * To change this template use File | Settings | File Templates.
 */
public class ECCSECTestModule extends AbstractModule {
    @Override
    protected void configure() {
        bind(ECCNamedCurveFp.class).to(SECNamedCurveFp.class);

        install(new FactoryModuleBuilder().implement(ECCCurve.class, ECCurveFp.class).build(ECCCurveFactory.class));
        install(new FactoryModuleBuilder().implement(ECCNamedCurveFp.class, SECNamedCurveFp.class).build(ECCNamedCurveFactory.class));
        install(new FactoryModuleBuilder().implement(ECCParameters.class, ECParametersFp.class).build(ECCParametersFactory.class));
        install(new FactoryModuleBuilder().implement(ECCFieldElement.class, ECFieldElementFp.class).build(ECCFieldElementFactory.class));
        install(new FactoryModuleBuilder().implement(ECCPoint.class, ECPointFp.class).build(ECCPointFactory.class));
        install(new FactoryModuleBuilder().implement(ECCKeyPair.class, ECKeyPairFp.class).build(ECCKeyPairFactory.class));
        install(new FactoryModuleBuilder().implement(ECCSignature.class, ECSignatureFp.class).build(ECCSignatureFactory.class));

        // Message signing
        install(new FactoryModuleBuilder().implement(ECCMessageSigner.class, ECMessageSignerFp.class).build(ECCMessageSignerFactory.class));
        install(new FactoryModuleBuilder().implement(Hash.class, SingleSha1Hash.class).build(ECCMessageSignerHashFactory.class));
        bind(BigIntegerRandom.class).to(RealBigIntegerRandom.class);
        install(new FactoryModuleBuilder().implement(Random.class, Random.class).build(RandomFactory.class));
        install(new FactoryModuleBuilder().implement(ECCMessageSignatureVerifier.class, ECMessageSignatureVerifierFp.class).build(ECCMessageSignatureVerifierFactory.class));
    }
}
