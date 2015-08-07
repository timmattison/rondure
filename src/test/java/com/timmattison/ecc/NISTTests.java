package com.timmattison.ecc;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.timmattison.crypto.ecc.fp.SECNamedCurveFp;
import com.timmattison.crypto.ecc.interfaces.ECCParameters;
import com.timmattison.crypto.ecc.interfaces.ECCPoint;
import com.timmattison.crypto.modules.ECCSECTestModule;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;

/**
 * Created with IntelliJ IDEA.
 * User: Tim
 * Date: 8/16/13
 * Time: 7:24 PM
 * To change this template use File | Settings | File Templates.
 */
public class NISTTests {
    public static final String TEST_CSV = "/test.csv";
    public static final String NEW_LINE = "\n";
    public static final int CURVE_FIELD_NUMBER = 0;
    public static final int K_FIELD_NUMBER = 1;
    public static final int X_FIELD_NUMBER = 2;
    public static final int Y_FIELD_NUMBER = 3;
    public static final int DECIMAL = 10;
    public static final int HEXADECIMAL = 16;
    public static final String NIST_P_192_CURVE_NAME = "P192";
    public static final String NIST_P_224_CURVE_NAME = "P224";
    public static final String NIST_P_256_CURVE_NAME = "P256";
    public static final String NIST_P_384_CURVE_NAME = "P384";
    public static final String NIST_P_521_CURVE_NAME = "P521";
    Injector injector = Guice.createInjector(new ECCSECTestModule());
    private SECNamedCurveFp secNamedCurveFp;
    private ECCParameters secp192r1Params;
    private ECCParameters secp224r1Params;
    private ECCParameters secp256r1Params;
    private ECCParameters secp384r1Params;
    private ECCParameters secp521r1Params;
    private Map<String, ECCParameters> params;
    private Map<String, ECCPoint> basePoints = new HashMap<String, ECCPoint>();

    @Before
    public void setup() {
        Injector injector = Guice.createInjector(new ECCSECTestModule());
        secNamedCurveFp = injector.getInstance(SECNamedCurveFp.class);
        secp192r1Params = secNamedCurveFp.getSecp192r1();
        secp224r1Params = secNamedCurveFp.getSecp224r1();
        secp256r1Params = secNamedCurveFp.getSecp256r1();
        secp384r1Params = secNamedCurveFp.getSecp384r1();
        secp521r1Params = secNamedCurveFp.getSecp521r1();

        params = new HashMap<String, ECCParameters>();
        params.put(NIST_P_192_CURVE_NAME, secp192r1Params);
        params.put(NIST_P_224_CURVE_NAME, secp224r1Params);
        params.put(NIST_P_256_CURVE_NAME, secp256r1Params);
        params.put(NIST_P_384_CURVE_NAME, secp384r1Params);
        params.put(NIST_P_521_CURVE_NAME, secp521r1Params);
    }

    @Test
    public void inputDataMustNotBeNull() throws IOException {
        String[] lines = getLines();

        Assert.assertThat(lines, is(notNullValue()));
    }

    @Test
    public void inputDataIsValid() throws IOException {
        String[] lines = getLines();

        for (String line : lines) {
            String[] fields = splitRecord(line);

            Assert.assertThat("Incorrect number of fields", fields.length, is(4));
            Assert.assertThat("Did not find curve in curve list", params.get(fields[0]), is(notNullValue()));
        }
    }

    private String[] splitRecord(String line) {
        return line.split(",");
    }

    private String readFile(String filename) throws IOException {
        byte[] bytes = IOUtils.toByteArray(new InputStreamReader(filename.getClass().getResourceAsStream(filename), "ISO-8859-1"), "ISO-8859-1");

        return new String(bytes);
    }

    private String[] getLines() throws IOException {
        String file = readFile(TEST_CSV);
        String[] lines = file.split(NEW_LINE);

        return lines;
    }

    @Test
    public void testVectorsShouldMatch() throws IOException {
        String[] lines = getLines();

        for (String line : lines) {
            String[] fields = splitRecord(line);
            String curveName = fields[CURVE_FIELD_NUMBER];
            String kString = fields[K_FIELD_NUMBER];
            String xString = fields[X_FIELD_NUMBER];
            String yString = fields[Y_FIELD_NUMBER];
            ECCParameters eccParameters = params.get(curveName);

            BigInteger k = new BigInteger(kString, DECIMAL);
            ECCPoint xy = ECCTestHelper.getPoint(injector, eccParameters, new BigInteger(xString, HEXADECIMAL), new BigInteger(yString, HEXADECIMAL));

            if (k.equals(BigInteger.ONE)) {
                basePoints.put(curveName, xy);
            }

            ECCPoint P = basePoints.get(curveName);

            Assert.assertThat("Base point for " + curveName + " not found.  No record with k == 1 for this curve.", P, is(notNullValue()));

            ECCPoint kP = P.multiply(k);

            Assert.assertThat("X coordinates didn't match for " + curveName + ", " + kString, xy.getX(), is(kP.getX()));
            Assert.assertThat("Y coordinates didn't match for " + curveName + ", " + kString, xy.getY(), is(kP.getY()));
        }
    }
}
