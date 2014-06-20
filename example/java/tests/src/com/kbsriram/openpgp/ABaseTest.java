package com.kbsriram.openpgp;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public abstract class ABaseTest
{
    protected static final File ROOT = new File("../../tests");

    protected static final PGPPublicKeyRing readPublicKeyRing(String relpath)
        throws IOException, PGPException
    {
        BufferedInputStream bin = null;
        try {
            bin =
            new BufferedInputStream
            (new FileInputStream
             (new File(ROOT, relpath)));

            return
                new PGPPublicKeyRing(bin, new BcKeyFingerprintCalculator());
        }
        finally {
            if (bin != null) {
                try { bin.close(); }
                catch (IOException ioe) {}
            }
        }
    }
}
