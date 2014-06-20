package com.kbsriram.openpgp;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CSignatureTest
    extends ABaseTest
{
    @Test
    public void ensureCorrectSubkey()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("sig-misused-subkey/misused-subkey.pkr");
        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        assertEquals("", utils_pkr.getErrors());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("misused@sub.key", uids.get(0).getName());
        List<CPGPUtils.Subkey> subkeys = utils_pkr.getSubkeys();
        assertEquals(1, subkeys.size());
        assertEquals(utils_pkr.getEncryptionKey(),
                     subkeys.get(0).getPublicKey());

        FileInputStream fin = new FileInputStream
            (new File(ROOT, "sig-misused-subkey/hello.txt"));
        byte[] data = new byte[fin.available()];
        fin.read(data);
        fin.close();

        PGPSignature sig = readSignature("sig-misused-subkey/hello.txt.sig");
        // Should not be able to find a signing key for this id.
        List<PGPPublicKey> signers =
            utils_pkr.getSigningKeysByKeyID(sig.getKeyID());
        assertEquals(0, signers.size());

        // But this one should be good.
        sig = readSignature("sig-misused-subkey/hello-good.txt.sig");
        signers =
            utils_pkr.getSigningKeysByKeyID(sig.getKeyID());
        assertEquals(1, signers.size());

        // check signature for good measure.

        sig.init(new BcPGPContentVerifierBuilderProvider(), signers.get(0));
        sig.update(data);
        assertTrue(sig.verify());
    }

    private final static PGPSignature readSignature(String path)
        throws PGPException, IOException
    {
        BufferedInputStream bin =
            new BufferedInputStream
            (new FileInputStream
             (new File(ROOT, path)));

        PGPObjectFactory fact = new PGPObjectFactory(bin);
        PGPSignatureList siglist = (PGPSignatureList) fact.nextObject();
        assertNull(fact.nextObject());
        bin.close();

        assertEquals(1, siglist.size());
        return siglist.get(0);
    }
}
