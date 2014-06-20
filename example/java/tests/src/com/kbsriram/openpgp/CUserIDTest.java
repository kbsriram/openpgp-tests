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

public class CUserIDTest
    extends ABaseTest
{

    @Test
    public void unsignedUID()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-unsigned-uid/unsigned-uid.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("good userid <good@user.id>", uids.get(0).getName());
        assertEquals
            ("Name 'bad userid <bad@user.id>' rejected because no self-signatures were found.\n", utils_pkr.getErrors());
    }

    @Test
    public void revokedUID()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-revoked-uid/pk-revoked-uid.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("valid <valid@good.key>", uids.get(0).getName());
        assertEquals
            ("Name 'revoked <revoked@bad.key>' revoked by signature (type=0x30) issued by keyid 0xbc056a28122520f\n", utils_pkr.getErrors());
    }

    @Test
    public void expiredUID()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-expired-uid/expired-uid.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("valid <valid@good.key>", uids.get(0).getName());
        assertEquals
            ("signature (type=0x13) issued by keyid 0xbc056a28122520f has expired\nName 'expired-key' rejected because no self-signatures were found.\n",
             utils_pkr.getErrors());
    }

    @Test
    public void invalidUID()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-invalid-uid-signature/invalid-signed-uid.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("good userid <good@user.id>", uids.get(0).getName());
        assertEquals
            ("Skipping certification signature (type=0x13) issued by keyid 0x83c2d447eb26d2a3 for 'bad userid <bad@user.id>' because its public key is unavailable.\nName 'bad userid <bad@user.id>' rejected because no self-signatures were found.\n", utils_pkr.getErrors());
    }
}
