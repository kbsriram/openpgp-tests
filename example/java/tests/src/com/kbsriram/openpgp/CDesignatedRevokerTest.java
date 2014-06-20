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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CDesignatedRevokerTest
    extends ABaseTest
{

    @Test
    public void doit()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing revoker_pkr = readPublicKeyRing
            ("pk-designated-revoker/revoker.pkr");
        final PGPPublicKeyRing must_not_revoke_target_pkr = readPublicKeyRing
            ("pk-designated-revoker/must_not_revoke_target.pkr");
        final PGPPublicKeyRing must_revoke_target_pkr = readPublicKeyRing
            ("pk-designated-revoker/must_revoke_target.pkr");

        CPGPUtils.PrimaryKeyFinder kf = new CPGPUtils.PrimaryKeyFinder() {
                public List<PGPPublicKey> findByKeyID(long kid) {
                    System.out.println
                        ("Asked to check for 0x"+Long.toHexString(kid));
                    if (revoker_pkr.getPublicKey().getKeyID() == kid) {
                        return Arrays.asList(revoker_pkr.getPublicKey());
                    }
                    else {
                        return null;
                    }
                }
            };

        CPGPUtils.PKR utils_revoker_pkr =
            CPGPUtils.validate(revoker_pkr, null);
        CPGPUtils.PKR utils_must_not_revoke_target_pkr =
            CPGPUtils.validate(must_not_revoke_target_pkr, kf);
        CPGPUtils.PKR utils_must_revoke_target_pkr =
            CPGPUtils.validate(must_revoke_target_pkr, kf);
        assertEquals(CPGPUtils.PKR.Status.REVOKED,
                     utils_must_revoke_target_pkr.getStatus());
    }
}
