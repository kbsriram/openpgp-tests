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

public class CCertificationsTest
    extends ABaseTest
{
    @Test
    public void certifications()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing apkr = readPublicKeyRing
            ("pk-certifications/a-certifier.pkr");

        CPGPUtils.PKR utils_apkr = CPGPUtils.validate(apkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_apkr.getStatus());
        List<CPGPUtils.UserID> auids = utils_apkr.getUserIDs();
        assertEquals(1, auids.size());
        assertEquals("certifier A <a@certifier.key>", auids.get(0).getName());
        assertEquals(0, utils_apkr.getErrors().length());

        final PGPPublicKeyRing bpkr = readPublicKeyRing
            ("pk-certifications/b-certifier.pkr");

        CPGPUtils.PKR utils_bpkr = CPGPUtils.validate(bpkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_bpkr.getStatus());
        List<CPGPUtils.UserID> buids = utils_bpkr.getUserIDs();
        assertEquals(1, buids.size());
        assertEquals("certifier B <b@certifier.key>", buids.get(0).getName());
        assertEquals(0, utils_bpkr.getErrors().length());

        CPGPUtils.PrimaryKeyFinder kf = new CPGPUtils.PrimaryKeyFinder() {
                public List<PGPPublicKey> findByKeyID(long kid) {
                    if (apkr.getPublicKey().getKeyID() == kid) {
                        return Arrays.asList(apkr.getPublicKey());
                    }
                    else if (bpkr.getPublicKey().getKeyID() == kid) {
                        return Arrays.asList(bpkr.getPublicKey());
                    }
                    else {
                        return null;
                    }
                }
            };

        final PGPPublicKeyRing targetpkr = readPublicKeyRing
            ("pk-certifications/target.pkr");

        CPGPUtils.PKR utils_targetpkr = CPGPUtils.validate(targetpkr, kf);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_targetpkr.getStatus());
        List<CPGPUtils.UserID> targetuids = utils_targetpkr.getUserIDs();
        assertEquals(2, targetuids.size());
        CPGPUtils.UserID uid0 = targetuids.get(0);
        assertEquals("target2 <target2@key.net>", uid0.getName());
        assertEquals(0, uid0.getCertifications().size());
        CPGPUtils.UserID uid1 = targetuids.get(1);
        assertEquals("target1 <target1@key.net>", uid1.getName());
        assertEquals(1, uid1.getCertifications().size());
        assertEquals(uid1.getCertifications().get(0).getSigner(),
                     bpkr.getPublicKey());
        assertEquals
            ("signature (type=0x30) issued by keyid 0x6bc2be65ab6dc7ba revoked 'target2 <target2@key.net>', removing its certification.\nSkipping certification signature (type=0x10) issued by keyid 0x6bc2be65ab6dc7ba for 'target1 <target1@key.net>' because the signature is invalid.\n", utils_targetpkr.getErrors());
    }
}
