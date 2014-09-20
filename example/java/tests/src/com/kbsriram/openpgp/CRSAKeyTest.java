package com.kbsriram.openpgp;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CRSAKeyTest
    extends ABaseTest
{
    @Test
    public void validateSmallFactors()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("rsa-small-factor/rsa-small-factor.pkr");
        try {
            CPGPUtils.validate(pkr, null);
            fail("Did not catch small factor rsa key.");
        }
        catch (PGPException pge) {
            assertEquals("modulus has a small factor (101)", pge.getMessage());
        }
    }

    @Test
    public void validateBadExponent()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("rsa-bad-exponent/rsa-bad-exponent.pkr");
        try {
            CPGPUtils.validate(pkr, null);
            fail("Did not catch bad exponent rsa key.");
        }
        catch (PGPException pge) {
            assertEquals("exponent must be >= 3", pge.getMessage());
        }
    }
}
