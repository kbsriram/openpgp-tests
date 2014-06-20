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

public class CSubkeyTest
    extends ABaseTest
{

    @Test
    public void expiredSubkey()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-expired-subkey/expired-subkey.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("expired-subkey", uids.get(0).getName());
        List<CPGPUtils.Subkey> subkeys = utils_pkr.getSubkeys();
        assertEquals(0, subkeys.size());
        assertNull(utils_pkr.getEncryptionKey());
        assertEquals
            ("signature (type=0x18) issued by keyid 0xec8a174198c8397d has expired\nSubkey 0xa5df81600d3c909b rejected because no valid binding signatures were found.\n", utils_pkr.getErrors());
    }

    @Test
    public void invalidSigningSubkey()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-invalid-signing-subkey/invalid-signing-subkey.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("invalid-signing-subkeys", uids.get(0).getName());
        List<CPGPUtils.Subkey> subkeys = utils_pkr.getSubkeys();
        assertEquals(0, subkeys.size());
        assertNull(utils_pkr.getEncryptionKey());
        assertEquals
            ("Rejecting signature (type=0x18) issued by keyid 0xedd40d05081e923f for subkey 0xb68ab7e27fae30f2 because it doesn't have a cross-certification.\nSee https://www.gnupg.org/faq/subkey-cross-certify.html\nSubkey 0xb68ab7e27fae30f2 rejected because no valid binding signatures were found.\nSubkey 0xa95659c566684ee7 rejected because no valid binding signatures were found.\n", utils_pkr.getErrors());
    }

    @Test
    public void invalidSubkeySignature()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-invalid-subkey-signature/invalid-signed-subkey.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("certifying subkey", uids.get(0).getName());
        List<CPGPUtils.Subkey> subkeys = utils_pkr.getSubkeys();
        assertEquals(1, subkeys.size());
        assertNull(utils_pkr.getEncryptionKey());
        assertEquals
            ("Subkey 0x24e5ef1d28b2ed0c rejected because no valid binding signatures were found.\n", utils_pkr.getErrors());
    }

    @Test
    public void revokedSubkey()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-revoked-subkey/revoked-subkey.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("revoked-subkey", uids.get(0).getName());
        List<CPGPUtils.Subkey> subkeys = utils_pkr.getSubkeys();
        assertEquals(0, subkeys.size());
        assertNull(utils_pkr.getEncryptionKey());
        assertEquals
            ("Subkey 0x79136d87c8bf1e28 revoked by signature (type=0x28) issued by keyid 0x134974721f4867f9\nSubkey 0x9d7d4ee8defee017 revoked by signature (type=0x28) issued by keyid 0x134974721f4867f9\n", utils_pkr.getErrors());
    }

    @Test
    public void unsignedSubkey()
        throws PGPException, IOException, SignatureException
    {
        final PGPPublicKeyRing pkr = readPublicKeyRing
            ("pk-unsigned-subkey/unsigned-subkey.pkr");

        CPGPUtils.PKR utils_pkr = CPGPUtils.validate(pkr, null);
        assertEquals(CPGPUtils.PKR.Status.OK, utils_pkr.getStatus());
        List<CPGPUtils.UserID> uids = utils_pkr.getUserIDs();
        assertEquals(1, uids.size());
        assertEquals("unsigned subkey <unsigned@sub.key>",
                     uids.get(0).getName());
        List<CPGPUtils.Subkey> subkeys = utils_pkr.getSubkeys();
        assertEquals(0, subkeys.size());
        assertNull(utils_pkr.getEncryptionKey());
        assertEquals
            ("Subkey 0x1df66843170da987 rejected because no valid binding signatures were found.\n", utils_pkr.getErrors());
    }
}
