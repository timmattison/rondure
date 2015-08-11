package com.timmattison.ecc;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.timmattison.crypto.ecc.interfaces.ECCParameters;
import com.timmattison.crypto.ecc.interfaces.ECCPoint;
import com.timmattison.crypto.modules.ECCSECTestModule;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

/**
 * Created with IntelliJ IDEA.
 * User: timmattison
 * Date: 5/10/13
 * Time: 7:23 AM
 * To change this template use File | Settings | File Templates.
 */
public class SmallCurveTest {
    private final Injector injector = Guice.createInjector(new ECCSECTestModule());
    private Random random;

    @Before
    public void setup() {
        random = new Random(0);
    }

    @Test
    public void testMultiplyInfinity() throws Exception {
        ECCParameters smallCurve = ECCTestHelper.getSmallCurve1Parameters(injector);
        ECCPoint result = smallCurve.getG().multiply(smallCurve.getN());

        Assert.assertTrue(result.isInfinity());
    }

    @Test
    public void testECDH1() {
        ECCPoint basePoint = ECCTestHelper.getBasePoint(injector);

        BigInteger alicePrivateKey = BigInteger.valueOf(3);
        ECCPoint alicePublicKey = basePoint.multiply(alicePrivateKey);

        BigInteger bobPrivateKey = BigInteger.valueOf(10);
        ECCPoint bobPublicKey = basePoint.multiply(bobPrivateKey);

        ECCPoint aliceJointSecret = bobPublicKey.multiply(alicePrivateKey);
        ECCPoint bobJointSecret = alicePublicKey.multiply(bobPrivateKey);

        Assert.assertTrue(aliceJointSecret.equals(bobJointSecret));
    }

    @Test
    public void testMultiply13P() {
        ECCPoint thirteenthPoint = ECCTestHelper.getBasePoint(injector).multiply(BigInteger.valueOf(13));
        validatePoint(thirteenthPoint, 16, 4);
    }

    @Test
    public void testDoubleBasePoint() {
        ECCPoint result = ECCTestHelper.getBasePoint(injector).twice();

        Assert.assertTrue(result.getX().toBigInteger().equals(new BigInteger("6")));
        Assert.assertTrue(result.getY().toBigInteger().equals(new BigInteger("3")));
    }

    private void validatePoint(ECCPoint point, int x, int y) {
        Assert.assertTrue(point.getX().toBigInteger().equals(BigInteger.valueOf(x)));
        Assert.assertTrue(point.getY().toBigInteger().equals(BigInteger.valueOf(y)));
    }

    @Test
    public void testCalculateUpTo18P() {
        ECCPoint basePoint = ECCTestHelper.getBasePoint(injector);
        ECCPoint nextPoint = ECCTestHelper.getBasePoint(injector).twice();

        // Test 3P: 10, 6
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 10, 6);

        // Test 4P: 3, 1
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 3, 1);

        // Test 5P: 9, 16
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 9, 16);

        // Test 6P: 16, 13
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 16, 13);

        // Test 7P: 0, 6
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 0, 6);

        // Test 8P: 13, 7
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 13, 7);

        // Test 9P: 7, 6
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 7, 6);

        // Test 10P: 7, 11
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 7, 11);

        // Test 11P: 13, 10
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 13, 10);

        // Test 12P: 0, 11
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 0, 11);

        // Test 13P: 16, 4
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 16, 4);

        // Test 14P: 9, 1
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 9, 1);

        // Test 15P: 3, 16
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 3, 16);

        // Test 16P: 10, 11
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 10, 11);

        // Test 17P: 6, 14
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 6, 14);

        // Test 18P: 5, 16
        nextPoint = nextPoint.add(basePoint);
        validatePoint(nextPoint, 5, 16);
    }

    @Test
    public void testCalculate19P() {
        ECCPoint firstPoint = ECCTestHelper.getPoint(injector, ECCTestHelper.getSmallCurve1Parameters(injector), new BigInteger("5"), new BigInteger("1"));
        ECCPoint nextPoint = firstPoint.twice();

        for (int loop = 3; loop < 19; loop++) {
            nextPoint = nextPoint.add(firstPoint);
        }

        nextPoint = nextPoint.add(firstPoint);

        Assert.assertTrue(nextPoint.isInfinity());
    }

    @Test
    public void testCalculateFourthPoint() {
        ECCPoint firstPoint = ECCTestHelper.getPoint(injector, ECCTestHelper.getSmallCurve1Parameters(injector), new BigInteger("5"), new BigInteger("1"));
        ECCPoint secondPoint = firstPoint.twice();
        ECCPoint thirdPoint = secondPoint.add(firstPoint);
        ECCPoint fourthPoint = thirdPoint.add(firstPoint);

        Assert.assertTrue(fourthPoint.getX().toBigInteger().equals(new BigInteger("3")));
        Assert.assertTrue(fourthPoint.getY().toBigInteger().equals(new BigInteger("1")));
    }

    @Test
    public void testGenerateBasePoint() {
        ECCParameters eccParameters = ECCTestHelper.getSmallCurve1Parameters(injector);

        for (int loop = 0; loop < 256; loop++) {
            ECCPoint basePoint = eccParameters.getCurve().generateBasePoint(random);

            if (basePoint != null) {
                // Found a base point, success!
                return;
            }
        }

        Assert.fail("No base point found");
    }
}
