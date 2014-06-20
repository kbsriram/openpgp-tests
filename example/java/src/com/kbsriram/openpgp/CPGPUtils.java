package com.kbsriram.openpgp;

import org.bouncycastle.util.encoders.Hex;
import java.util.Map;
import java.util.Arrays;
import java.util.HashMap;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

public class CPGPUtils
{
    /**
     * <p>Encapsulates filtered information about a verified userid
     * within the PKR class.</p>
     */
    public final static class UserID
    {
        public String getName()
        { return m_uid; }
        public List<PGPSignature> getSelfSignatures()
        { return m_sigs; }
        /**
         * @return a list of verified certifications for this userid.
         */
        public List<Certification> getCertifications()
        { return m_certs; }
        private UserID
            (String uid, List<PGPSignature> sigs, List<Certification> certs)
        {
            m_uid = uid;
            m_sigs = sigs;
            m_certs = certs;
        }
        private final String m_uid;
        private final List<PGPSignature> m_sigs;
        private final List<Certification> m_certs;
    }

    /**
     * <p>Encapsulates filtered information about a verified userid
     * within the PKR class.</p>
     */
    public final static class UserAttribute
    {
        public PGPUserAttributeSubpacketVector getUserAttribute()
        { return m_attr; }
        public List<PGPSignature> getSelfSignatures()
        { return m_sigs; }
        /**
         * @return a list of verified certifications for this userid.
         */
        public List<Certification> getCertifications()
        { return m_certs; }
        private UserAttribute(PGPUserAttributeSubpacketVector attr,
                              List<PGPSignature> sigs,
                              List<Certification> certs)
        {
            m_attr = attr;
            m_sigs = sigs;
            m_certs = certs;
        }
        private final PGPUserAttributeSubpacketVector m_attr;
        private final List<PGPSignature> m_sigs;
        private final List<Certification> m_certs;
    }

    /**
     * <p>Provides access to a verified subkey within the PKR.</p>
     */
    public final static class Subkey
    {
        /**
         * @return a list of signatures that sucessfully
         * bound this subkey to the primary key.
         */
        public List<PGPSignature> getSignatures()
        { return m_sigs; }
        public PGPPublicKey getPublicKey()
        { return m_subkey; }

        private Subkey(PGPPublicKey subkey, List<PGPSignature> sigs)
        {
            m_subkey = subkey;
            m_sigs = sigs;
        }
        private final PGPPublicKey m_subkey;
        private final List<PGPSignature> m_sigs;
    }

    /**
     * <p>A certification is an assertion made by a different
     * public key, about the userid or userattribute within
     * the PKR.</p>
     */
    public final static class Certification
    {
        public PGPSignature getSignature()
        { return m_sig; }
        /**
         * <p>This is the public key signed this certification.</p>
         */
        public PGPPublicKey getSigner()
        { return m_signer; }
        private void setSignature(PGPSignature sig)
        { m_sig = sig; }
        private Certification(PGPPublicKey signer, PGPSignature sig)
        {
            m_signer = signer;
            m_sig = sig;
        }
        private final PGPPublicKey m_signer;
        private PGPSignature m_sig;
    }

    /**
     * <p>This class provides filtered access to verified
     * userids, user attributes and subkeys from a raw
     * PGPPublicKeyRing.</p>
     *
     * <p>Initialized using the
     * {@link CPGPUtils#validate(PGPPublicKeyRing, PrimaryKeyFinder) validate}
     * method</p>
     */
    public final static class PKR
    {
        public enum Status { OK, REVOKED, UNUSABLE };

        public PGPPublicKeyRing getOriginal()
        { return m_pkr; }
        /**
         * <p>Just a log of any errors encountered while examining
         * the keyring. Since many errors are skipped, you can
         * have a PKR with status <tt>OK</tt> as well as errors
         * here.</p>
         */
        public String getErrors()
        { return m_errors.toString(); }
        public Status getStatus()
        { return m_status; }
        /**
         * @return a list of verified userids within the keyring.
         */
        public List<UserID> getUserIDs()
        { return m_uids; }
        /**
         * @return a list of verified attributes within the keyring.
         */
        public List<UserAttribute> getUserAttributes()
        { return m_attrs; }
        /**
         * @return a list of verified subkeys within the keyring.
         */
        public List<Subkey> getSubkeys()
        { return m_subkeys; }
        /**
         * @return the best available verified encryption key for this keyring.
         * May return null if none available.
         */
        public PGPPublicKey getEncryptionKey()
        { return m_encrypt_key; }
        /**
         * @param keyid is the id to use when searching.
         *
         * @return a list of PGPPublicKeys that match the provided
         * keyid, and are usable for checking signatures. The list is
         * almost certain to have atmost one entry, but technically
         * it's possible to have multiple keys with the same keyid.
         */
        public List<PGPPublicKey> getSigningKeysByKeyID(long keyid)
        {
            List<PGPPublicKey> ret = new ArrayList<PGPPublicKey>();

            // First check if we're the primary key.
            PGPPublicKey masterpk = m_pkr.getPublicKey();
            if (masterpk.getKeyID() == keyid) {
                // Check if the main key is usable by checking for an
                // appropriate use flag in its verified self-signatures.
                uidloop:
                for (UserID uid: getUserIDs()) {
                    for (PGPSignature sig: uid.getSelfSignatures()) {
                        if (hasKeyFlag(sig, KeyFlags.SIGN_DATA)) {
                            ret.add(masterpk);
                            break uidloop;
                        }
                    }
                }
            }
            // Check verified subkeys as well.
            for (Subkey subkey: getSubkeys()) {
                PGPPublicKey candidate = subkey.getPublicKey();
                if (candidate.getKeyID() == keyid) {
                    for (PGPSignature sig: subkey.getSignatures()) {
                        if (hasKeyFlag(sig, KeyFlags.SIGN_DATA)) {
                            ret.add(candidate);
                            break;
                        }
                    }
                }
            }
            return ret;
        }

        private PKR
            (Status status,
             PGPPublicKeyRing pkr,
             List<byte[]> designated_revoker_fps,
             List<PGPSignature> primary_revoking_sigs,
             List<UserID> uids,
             List<UserAttribute> attrs,
             List<Subkey> subkeys,
             PGPPublicKey encrypt_key,
             StringBuilder errors)
        {
            m_status = status;
            m_pkr = pkr;
            m_designated_revoker_fps = designated_revoker_fps;
            m_primary_revoking_sigs = primary_revoking_sigs;
            m_uids = uids;
            m_attrs = attrs;
            m_subkeys = subkeys;
            m_encrypt_key = encrypt_key;
            m_errors = errors;
        }
        private final Status m_status;
        private final PGPPublicKeyRing m_pkr;
        private final List<byte[]> m_designated_revoker_fps;
        private final List<PGPSignature> m_primary_revoking_sigs;
        private final List<UserID> m_uids;
        private final List<UserAttribute> m_attrs;
        private final List<Subkey> m_subkeys;
        private final PGPPublicKey m_encrypt_key;
        private final StringBuilder m_errors;
    }

    private final static class KeyInfo
    {
        private KeyInfo() {}
        private PGPPublicKey getKey()
        { return m_pk; }
        private void setKey(PGPPublicKey pk)
        { m_pk = pk; }
        private void maybeUpdateIfEncrypt(PGPSignature sig, PGPPublicKey pk)
        {
            if (!hasKeyFlag
                (sig, KeyFlags.ENCRYPT_STORAGE|KeyFlags.ENCRYPT_COMMS)) {
                return;
            }
            long cur = sig.getCreationTime().getTime();
            if ((m_pk != null) && (cur < m_last_ts)) { return; }
            m_pk = pk;
            m_last_ts = cur;
        }
        private long m_last_ts = 0l;
        private PGPPublicKey m_pk = null;
    }

    /**
     * <p>Interface to peek into your keystore, so that certifications
     * made by other keys can be checked.</p>
     */
    public interface PrimaryKeyFinder
    {
        /**
         * @return all the public keys in your keystore that match
         * the provided keyid. You may return null here as well
         * if you can't find any keys.
         */
        List<PGPPublicKey> findByKeyID(long keyid);
    }

    /**
     * <p>This is the primary way to use this utility. It examines
     * a provided PGPPublicKeyRing, an optional interface to search for
     * related keys into your keystore, and returns a wrapped object
     * that provides access only to verified key material.</p>
     *
     * @param pkr is the keyring to be examined.
     * @param kf is an interface to look for related keys into your keystore. May be null.
     * @return an object that provides filtered access to verified key material.
     */
    @SuppressWarnings("unchecked")
    public final static PKR validate(PGPPublicKeyRing pkr, PrimaryKeyFinder kf)
        throws PGPException, SignatureException, IOException
    {
        // First handle keyring revocation/designated revokers
        PGPPublicKey masterpk = pkr.getPublicKey();
        if (!masterpk.isMasterKey()) {
            throw new IllegalArgumentException
                ("Unexpected - first key is not master");
        }

        StringBuilder errors = new StringBuilder();

        List<byte[]> designated_revoker_fps = new ArrayList<byte[]>();
        List<PGPSignature> prim_revoking_sigs = new ArrayList<PGPSignature>();
        List<UserID> userids = new ArrayList<UserID>();
        List<UserAttribute> userattrs = new ArrayList<UserAttribute>();
        List<Subkey> subkeys = new ArrayList<Subkey>();
        KeyInfo einfo = new KeyInfo();

        Iterator<PGPSignature> master_sigit =
            masterpk.getSignaturesOfType(PGPSignature.DIRECT_KEY);
        while (master_sigit.hasNext()) {
            PGPSignature sig = master_sigit.next();
            maybeAddDesignated
                (designated_revoker_fps, sig, masterpk, errors);
        }

        // NB #1: .isRevoked() is not a complete implementation. For
        // instance, it doesn't verify whether signatures are actually
        // valid, and doesn't account for designated revokers.
        //
        // NB #2: I don't have a way to get just the keysigs. So, this
        // step is to get the library to do the check first, which it
        // runs on the keysigs alone. Then I add missing checks.
        if (masterpk.isRevoked()) {
            // Second pass - check for revocations.
            master_sigit =
                masterpk.getSignaturesOfType(PGPSignature.KEY_REVOCATION);
            while (master_sigit.hasNext()) {
                PGPSignature sig = master_sigit.next();
                maybeAddKeyRevocation
                    (prim_revoking_sigs, sig, masterpk, kf,
                     designated_revoker_fps, errors);
            }
        }
        // At this point, if we've revoked the primary key, we should
        // not be able to do anything at all with the rest of the
        // key.
        if (prim_revoking_sigs.size() > 0) {
            return new PKR
                (PKR.Status.REVOKED, pkr,
                 designated_revoker_fps,
                 prim_revoking_sigs,
                 userids, userattrs, subkeys, einfo.getKey(),
                 errors);
        }

        // Now filter for valid userids and attributes
        Iterator<String> uidit = masterpk.getUserIDs();
        while (uidit.hasNext()) {
            maybeAddUserID
                (userids, masterpk, uidit.next(), einfo, kf, errors);
        }

        Iterator<PGPUserAttributeSubpacketVector> attrit =
            masterpk.getUserAttributes();
        while (attrit.hasNext()) {
            maybeAddUserAttribute
                (userattrs, masterpk, attrit.next(), einfo, kf, errors);
        }

        // Don't bother with subkeys if we can't find a good self-signature.
        if ((userids.size() == 0) && (userattrs.size() == 0)) {
            return new PKR
                (PKR.Status.UNUSABLE, pkr,
                 designated_revoker_fps,
                 prim_revoking_sigs,
                 userids, userattrs, subkeys, einfo.getKey(),
                 errors);
        }

        // Now start checking subkeys.
        Iterator<PGPPublicKey> keysit = pkr.getPublicKeys();
        // Skip the first (master) key.
        keysit.next();

        while (keysit.hasNext()) {
            PGPPublicKey subkey = keysit.next();
            if (subkey.isMasterKey()) {
                throw new IllegalArgumentException("unexpected");
            }
            maybeAddSubkey(subkeys, masterpk, subkey, einfo, errors);
        }

        return new PKR
            (PKR.Status.OK, pkr,
             designated_revoker_fps,
             prim_revoking_sigs,
             userids, userattrs, subkeys, einfo.getKey(),
             errors);
    }

    @SuppressWarnings("unchecked")
    private final static void maybeAddUserID
        (List<UserID> uids, PGPPublicKey pk, String uid, KeyInfo einfo,
         PrimaryKeyFinder kf, StringBuilder errors)
        throws PGPException, SignatureException, IOException
    {
        Iterator <PGPSignature> sigit = pk.getSignaturesForID(uid);
        if (sigit == null) {
            errors.append("Reject name '"+uid+"' for "+nicePk(pk)+
                          " because no self-signatures were found.\n");
            return;
        }

        List<PGPSignature> valid = new ArrayList<PGPSignature>();
        Map<String,Certification> fp2certs =
            new HashMap<String, Certification>();

        KeyInfo signer_info = new KeyInfo();
        while (sigit.hasNext()) {
            PGPSignature sig = sigit.next();
            signer_info.setKey(null);

            switch (sig.getSignatureType()) {
            case PGPSignature.DEFAULT_CERTIFICATION:
            case PGPSignature.NO_CERTIFICATION:
            case PGPSignature.CASUAL_CERTIFICATION:
            case PGPSignature.POSITIVE_CERTIFICATION:
            case PGPSignature.CERTIFICATION_REVOCATION:
                if (isGoodUIDSignature
                    (sig, pk, uid, true, null, signer_info, errors)) {
                    if (sig.getSignatureType() ==
                        PGPSignature.CERTIFICATION_REVOCATION) {
                        // Reject this uid permanently.
                        errors.append
                            ("Name '"+uid+"' revoked by "+niceSig(sig)+"\n");
                        return;
                    }
                    valid.add(sig);
                }
                else if (isGoodUIDSignature
                         (sig, pk, uid, false, kf, signer_info, errors)) {
                    updateCertMap(fp2certs, sig, signer_info.getKey());
                }
                break;

            default:
                errors.append("Ignore "+niceSig(sig)+" for name '"+uid+"'\n");
                break;
            }
        }
        // We need atleast one good self-signature.
        if (valid.size() == 0) {
            errors.append
                ("Name '"+uid+
                 "' rejected because no self-signatures were found.\n");
            return;
        }

        revsort(valid);
        // update latest encryption key
        for (PGPSignature sig: valid) {
            einfo.maybeUpdateIfEncrypt(sig, pk);
        }

        uids.add
            (new UserID
             (uid, valid, filterCerts(fp2certs, "'"+uid+"'", errors)));
    }

    private final static void updateCertMap
        (Map<String, Certification> fp2certs, PGPSignature sig,
         PGPPublicKey signer)
    {
        String fp = Hex.toHexString(signer.getFingerprint());
        Certification cert = fp2certs.get(fp);
        if (cert == null) {
            cert = new Certification(signer, sig);
            fp2certs.put(fp, cert);
        }
        else {
            // Update to most recent signature.
            if (cert.getSignature().getCreationTime().getTime() <
                sig.getCreationTime().getTime()) {
                cert.setSignature(sig);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private final static void maybeAddSubkey
        (List<Subkey> subkeys, PGPPublicKey masterpk, PGPPublicKey subkey,
         KeyInfo einfo, StringBuilder errors)
        throws PGPException, SignatureException, IOException
    {
        Iterator <PGPSignature> sigit = subkey.getSignatures();
        if (sigit == null) {
            errors.append("Reject subkey "+nicePk(subkey)+
                          " because no binding signatures were found.\n");
            return;
        }

        List<PGPSignature> valid = new ArrayList<PGPSignature>();

        while (sigit.hasNext()) {
            PGPSignature sig = sigit.next();
            switch (sig.getSignatureType()) {
            case PGPSignature.SUBKEY_BINDING:
            case PGPSignature.SUBKEY_REVOCATION:
                if (isGoodSubkeySignature
                    (sig, masterpk, masterpk, subkey, errors)) {
                    if (sig.getSignatureType() ==
                        PGPSignature.SUBKEY_REVOCATION) {
                        // Reject this subkey permanently.
                        errors.append
                            ("Subkey "+nicePk(subkey)+" revoked by "+
                             niceSig(sig)+"\n");
                        return;
                    }
                    // signing subkeys must have an embedded back
                    // signature.
                    if (!hasKeyFlag(sig, KeyFlags.SIGN_DATA) ||
                        isGoodBackSignature(sig, masterpk, subkey, errors)) {
                        valid.add(sig);
                    }
                }
                break;

            default:
                errors.append("Ignore "+niceSig(sig)+" for subkey "+
                              nicePk(subkey)+"\n");
                break;
            }
        }
        // We need atleast one good binding.
        if (valid.size() == 0) {
            errors.append
                ("Subkey "+nicePk(subkey)+
                 " rejected because no valid binding signatures were found.\n");
            return;
        }

        revsort(valid);
        for (PGPSignature sig: valid) {
            einfo.maybeUpdateIfEncrypt(sig, subkey);
        }
        subkeys.add(new Subkey(subkey, valid));
    }

    @SuppressWarnings("unchecked")
    private final static void maybeAddUserAttribute
        (List<UserAttribute> attrs, PGPPublicKey pk,
         PGPUserAttributeSubpacketVector attr, KeyInfo einfo,
         PrimaryKeyFinder kf, StringBuilder errors)
        throws PGPException, SignatureException, IOException
    {
        Iterator <PGPSignature> sigit = pk.getSignaturesForUserAttribute(attr);
        if (sigit == null) {
            errors.append("Reject attribute for "+nicePk(pk)+
                          " because no self-signatures were found.\n");
            return;
        }

        List<PGPSignature> valid = new ArrayList<PGPSignature>();
        Map<String,Certification> fp2certs =
            new HashMap<String, Certification>();

        KeyInfo signer_info = new KeyInfo();
        while (sigit.hasNext()) {
            PGPSignature sig = sigit.next();

            switch (sig.getSignatureType()) {
            case PGPSignature.DEFAULT_CERTIFICATION:
            case PGPSignature.NO_CERTIFICATION:
            case PGPSignature.CASUAL_CERTIFICATION:
            case PGPSignature.POSITIVE_CERTIFICATION:
            case PGPSignature.CERTIFICATION_REVOCATION:
                if (isGoodAttributeSignature
                    (sig, pk, attr, true, null, signer_info, errors)) {
                    if (sig.getSignatureType() ==
                        PGPSignature.CERTIFICATION_REVOCATION) {
                        // Reject this attribute permanently.
                        errors.append
                            ("Attribute revoked by "+niceSig(sig)+"\n");
                        return;
                    }
                    valid.add(sig);
                }
                else if (isGoodAttributeSignature
                         (sig, pk, attr, false, kf, signer_info, errors)) {
                    updateCertMap(fp2certs, sig, signer_info.getKey());
                }
                break;

            default:
                errors.append("Ignore "+niceSig(sig)+" for attribute\n");
                break;
            }
        }
        // We need atleast one good self-signature.
        if (valid.size() == 0) {
            errors.append
                ("Attribute rejected because no self-signatures were found.\n");
            return;
        }

        revsort(valid);
        for (PGPSignature sig: valid) {
            einfo.maybeUpdateIfEncrypt(sig, pk);
        }
        attrs.add
            (new UserAttribute
             (attr, valid,
              filterCerts(fp2certs, "attribute", errors)));
    }

    private final static List<Certification> filterCerts
        (Map<String,Certification> fp2certs, String tag, StringBuilder errors)
    {
        List<Certification> certs = new ArrayList<Certification>();
        for (String fp: fp2certs.keySet()) {
            Certification cert = fp2certs.get(fp);
            int typ = cert.getSignature().getSignatureType();
            if ((typ >= PGPSignature.DEFAULT_CERTIFICATION) &&
                (typ <= PGPSignature.POSITIVE_CERTIFICATION)) {
                certs.add(cert);
            }
            else {
                errors.append
                    (niceSig(cert.getSignature())+
                     " revoked "+tag+", removing its certification.\n");
            }
        }
        return certs;
    }

    // Sort signatures in descending order by time, so the first
    // one should generally be the one to use.
    private final static void revsort(List<PGPSignature> sigs)
    {
        Collections.sort
            (sigs, new Comparator<PGPSignature>() {
                public int compare(PGPSignature a, PGPSignature b) {
                    long ats = a.getCreationTime().getTime();
                    long bts = b.getCreationTime().getTime();
                    if (ats < bts) { return 1; }
                    if (ats > bts) { return -1; }
                    return 0;
                }
            });
    }

    private final static void maybeAddKeyRevocation
        (List<PGPSignature> sigs, PGPSignature sig, PGPPublicKey masterpk,
         PrimaryKeyFinder kf, List<byte[]> designated_revokers,
         StringBuilder errors)
        throws PGPException, SignatureException, IOException
    {
        // Figure out if have any hints about who signed this
        // signature.
        long kid = sig.getKeyID();
        List<PGPPublicKey> candidate_signers = new ArrayList<PGPPublicKey>();
        if (kid == 0l) { // really means a missing keyid.
            candidate_signers.add(masterpk);
        }
        else if (kid == masterpk.getKeyID()) {
            candidate_signers.add(masterpk);
        }
        else if (kf != null) {
            List<PGPPublicKey> found = kf.findByKeyID(kid);
            if (found != null) {
                for (PGPPublicKey candidate: found) {
                    // Only if it is also a designated revoker.
                    if (matchFingerprint(designated_revokers, candidate)) {
                        candidate_signers.add(candidate);
                    }
                    else {
                        errors.append
                            ("Rejecting "+nicePk(candidate)+
                             " as revoking "+nicePk(masterpk)+
                             " because it is not a designated revoker\n");
                    }
                }
            }
        }

        if (candidate_signers.size() == 0) {
            errors.append
                ("Will not revoke "+nicePk(masterpk)+
                 " because the revoker 0x"+Long.toHexString(kid)+
                 " cannot be confirmed as a valid revoker.\n");
            return;
        }

        for (PGPPublicKey candidate: candidate_signers) {
            if (isGoodDirectSignature(sig, candidate, masterpk, errors)) {
                sigs.add(sig);
                return;
            }
        }
        errors.append
            ("Will not revoke "+nicePk(masterpk)+"\n");
    }

    private final static String nicePk(PGPPublicKey pk)
    { return "0x"+Long.toHexString(pk.getKeyID()); }

    private final static String niceSig(PGPSignature sig)
    {
        return "signature (type=0x"+Integer.toHexString(sig.getSignatureType())+
            ") issued by keyid 0x"+Long.toHexString(sig.getKeyID());
    }

    private final static boolean matchFingerprint
        (List<byte[]> fps, PGPPublicKey pk)
    {
        byte[] pkfp = pk.getFingerprint();
        for (byte[] fp: fps) {
            if (constantEquals(fp, pkfp)) { return true; }
        }
        return false;
    }

    private final static boolean constantEquals(byte[] a, byte[] b)
    {
        if (a.length != b.length) { return false; }
        int res = 0;
        for (int i=0; i<a.length; i++) {
            res |= (a[i] ^ b[i]);
        }
        return res == 0;
    }

    private final static void maybeAddDesignated
        (List<byte[]> fps, PGPSignature sig, PGPPublicKey masterpk,
         StringBuilder errors)
        throws PGPException,SignatureException, IOException
    {
        if (!isGoodDirectSignature(sig, masterpk, masterpk, errors)) { return; }
        PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
        if (hashed == null) {
            errors.append
                ("Designated revoking "+niceSig(sig)+
                 " is missing revocation key.\n");
            return;
        }
        SignatureSubpacket spack =
            hashed.getSubpacket(SignatureSubpacketTags.REVOCATION_KEY);
        if (spack == null) { return; }
        // You might think that the parser actually creates a RevocationKey
        // type, but no - you have to do that yourself.
        RevocationKey designated_revoker =
            new RevocationKey(spack.isCritical(), spack.getData());

        // 0x80 bit must be set
        if ((designated_revoker.getSignatureClass() & 0x80) == 0) { return; }
        // algorithm id must match
        if (designated_revoker.getAlgorithm() != masterpk.getAlgorithm()) {
            return;
        }
        fps.add(designated_revoker.getFingerprint());
    }

    private final static boolean hasKeyFlag(PGPSignature sig, int flag)
    {
        PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
        if (hashed == null) { return false; }

        KeyFlags flags = (KeyFlags)
            hashed.getSubpacket(SignatureSubpacketTags.KEY_FLAGS);
        if (flags == null) { return false; }
        return ((flags.getFlags() & flag) != 0);
    }

    private final static boolean isGoodSubkeySignature
        (PGPSignature sig, PGPPublicKey signer,
         PGPPublicKey primary, PGPPublicKey subkey,
         StringBuilder errors)
        throws PGPException,SignatureException,IOException
    {
        sig.init(new BcPGPContentVerifierBuilderProvider(), signer);

        return
            sig.verifyCertification(primary, subkey) &&
            isSignatureCurrent(sig, errors);
    }

    private final static boolean isGoodDirectSignature
        (PGPSignature sig, PGPPublicKey signer, PGPPublicKey target,
         StringBuilder errors)
        throws PGPException,SignatureException,IOException
    {
        sig.init(new BcPGPContentVerifierBuilderProvider(), signer);

        boolean ok;

        // There's a bug that prevents sig.verifyCertification(signer)
        // working for DIRECT_KEY signatures.
        //
        // So, re-implement the code again here.
        if (sig.getSignatureType() == PGPSignature.DIRECT_KEY) {
            byte[] bytes = target.getPublicKeyPacket().getEncodedContents();
            sig.update((byte)0x99);
            sig.update((byte)(bytes.length >> 8));
            sig.update((byte)(bytes.length));
            sig.update(bytes);
            ok = sig.verify();
        }
        else {
            ok = sig.verifyCertification(target);
        }

        // If we have a good signature, also ensure the signature
        // hasn't expired.
        return ok && isSignatureCurrent(sig, errors);
    }

    private final static boolean isGoodBackSignature
        (PGPSignature sig, PGPPublicKey signer, PGPPublicKey target,
         StringBuilder errors)
        throws PGPException,SignatureException,IOException
    {

        SignatureSubpacket esigpack = null;

        // Prefer to get it from the hashed subpacket.
        PGPSignatureSubpacketVector svec = sig.getHashedSubPackets();
        if (svec != null) {
            esigpack =
                svec.getSubpacket(SignatureSubpacketTags.EMBEDDED_SIGNATURE);
        }

        if (esigpack == null) {
            svec = sig.getUnhashedSubPackets();
            if (svec != null) {
                esigpack =
                    svec.getSubpacket
                    (SignatureSubpacketTags.EMBEDDED_SIGNATURE);
            }
        }

        if (esigpack == null) {
            errors.append
                ("Rejecting "+niceSig(sig)+
                 " for subkey "+nicePk(target)+
                 " because it doesn't have a cross-certification.\n"+
                 "See https://www.gnupg.org/faq/subkey-cross-certify.html\n");
            return false;
        }

        // Unfortunately, since PGPSignature(byte[]) is not public, we
        // have to go through this ugly contortion to get a signature.

        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        // dump out an old-style header.
        int hdr = 0x80 | (PacketTags.SIGNATURE << 2);
        int len = esigpack.getData().length;
        if (len <= 0xff) {
            baout.write(hdr);
            baout.write(len);
        }
        else if (len <= 0xffff) {
            baout.write(hdr|0x01);
            baout.write((len >> 8) & 0xff);
            baout.write(len & 0xff);
        }
        else {
            baout.write(hdr|0x02);
            baout.write((len >> 24) & 0xff);
            baout.write((len >> 16) & 0xff);
            baout.write((len >> 8) & 0xff);
            baout.write(len & 0xff);
        }

        baout.write(esigpack.getData());
        baout.close();

        PGPObjectFactory fact =
            new PGPObjectFactory
            (new ByteArrayInputStream
             (baout.toByteArray()));
        Object obj = fact.nextObject();

        if (!(obj instanceof PGPSignatureList)) {
            errors.append
                ("Rejecting "+niceSig(sig)+
                 " for subkey "+nicePk(target)+
                 " because no usable embedded signature is available.\n");
            return false;
        }
        PGPSignatureList esiglist = (PGPSignatureList) obj;
        if (esiglist.size() != 1) {
            errors.append
                ("Rejecting "+niceSig(sig)+
                 " for subkey "+nicePk(target)+
                 " because no usable embedded signature is available.\n");
            return false;
        }

        PGPSignature esig = esiglist.get(0);
        if (esig.getSignatureType() != PGPSignature.PRIMARYKEY_BINDING) {
            errors.append
                ("Rejecting "+niceSig(sig)+
                 " for subkey "+nicePk(target)+
                 " because the embedded "+niceSig(esig)+
                 " is not a proper backsignature.\n");
            return false;
        }
        return isGoodSubkeySignature
            (esig, target, signer, target, errors);
    }

    private final static boolean isGoodUIDSignature
        (PGPSignature sig, PGPPublicKey masterpk, String uid,
         boolean self, PrimaryKeyFinder kf, KeyInfo signer_info,
         StringBuilder errors)
        throws PGPException,SignatureException,IOException
    {
        List<PGPPublicKey> signers = findSigners
            (sig, masterpk, self, kf, "'"+uid+"'", errors);
        if (signers == null) { return false; }

        for (PGPPublicKey signer: signers) {
            sig.init(new BcPGPContentVerifierBuilderProvider(), signer);
            if (!sig.verifyCertification(uid, masterpk)) {
                errors.append
                    ("Skipping certification "+niceSig(sig)+" for '"+uid+
                     "' because the signature is invalid.\n");
                continue;
            }
            if (isSignatureCurrent(sig, errors)) {
                signer_info.setKey(signer);
                return true;
            }
        }
        return false;
    }

    private final static List<PGPPublicKey> findSigners
        (PGPSignature sig, PGPPublicKey masterpk, boolean self,
         PrimaryKeyFinder kf, String tag, StringBuilder errors)
    {
        List<PGPPublicKey> signers = null;
        if (self) {
            if (sig.getKeyID() != masterpk.getKeyID()) { return null; }
            signers = Arrays.asList(masterpk);
        }
        else {
            if (sig.getKeyID() == masterpk.getKeyID()) { return null; }
            if (kf != null) {
                signers = kf.findByKeyID(sig.getKeyID());
            }
        }
        if ((signers == null) || (signers.size() == 0)) {
            errors.append
                ("Skipping certification "+niceSig(sig)+" for "+tag+
                 " because its public key is unavailable.\n");
            return null;
        }
        return signers;
    }

    private final static boolean isGoodAttributeSignature
        (PGPSignature sig, PGPPublicKey masterpk,
         PGPUserAttributeSubpacketVector attr,
         boolean self, PrimaryKeyFinder kf, KeyInfo signer_info,
         StringBuilder errors)
        throws PGPException,SignatureException,IOException
    {
        List<PGPPublicKey> signers = findSigners
            (sig, masterpk, self, kf, "attribute", errors);
        if (signers == null) { return false; }

        for (PGPPublicKey signer: signers) {
            sig.init(new BcPGPContentVerifierBuilderProvider(), signer);
            if (!sig.verifyCertification(attr, masterpk)) {
                errors.append
                    ("Skipping certification "+niceSig(sig)+
                     " for attribute because the signature is invalid.\n");
                continue;
            }
            if (isSignatureCurrent(sig, errors)) {
                signer_info.setKey(signer);
                return true;
            }
        }
        return false;
    }

    private final static boolean isSignatureCurrent
        (PGPSignature sig, StringBuilder errors)
    {
        // The base code doesn't completely check whether a signature
        // actually has a creation timestamp. So, redo the check here
        // if needed.
        long cts = sig.getCreationTime().getTime();
        if ((cts == 0l) && (sig.getVersion() == 4)) {
            // Make sure we actually have a timestamp packet in
            // the hashed section.
            PGPSignatureSubpacketVector svec = sig.getHashedSubPackets();
            if (svec == null) {
                errors.append(niceSig(sig)+
                              " is missing a creation timestamp.\n");
                return false;
            }
            SignatureCreationTime tspack = (SignatureCreationTime)
                svec.getSubpacket(SignatureSubpacketTags.CREATION_TIME);
            if (tspack == null) {
                errors.append
                    (niceSig(sig)+" is missing a creation timestamp.\n");
                return false;
            }
            cts = tspack.getTime().getTime();
        }

        // Signature should not be in the future.

        if (cts > (System.currentTimeMillis() + ACCEPTABLE_DELTA_MSEC)) {
            errors.append(niceSig(sig)+" in the future? ("+new Date(cts)+")\n");
            return false;
        }
        if (cts < 0) {
            errors.append(niceSig(sig)+ " is negative? ("+cts+")\n");
            return false;
        }

        // Check if the signature or key has expired.
        PGPSignatureSubpacketVector svec = sig.getHashedSubPackets();
        if (svec != null) {
            SignatureExpirationTime tspack = (SignatureExpirationTime)
                svec.getSubpacket(SignatureSubpacketTags.EXPIRE_TIME);
            if (tspack != null) {
                long exp_delta = tspack.getTime()*1000l;
                if (!acceptableInterval(sig, cts, exp_delta, errors)) {
                    return false;
                }
            }
            // If there's a key-expiration subpacket, also check that.
            KeyExpirationTime ket =  (KeyExpirationTime)
                svec.getSubpacket(SignatureSubpacketTags.KEY_EXPIRE_TIME);
            if (ket != null) {
                long exp_delta = ket.getTime()*1000l;
                if (!acceptableInterval(sig, cts, exp_delta, errors)) {
                    return false;
                }
            }
        }

        return true;
    }

    private final static boolean acceptableInterval
        (PGPSignature sig, long start, long delta, StringBuilder errors)
    {
        if (delta < 0) {
            errors.append
                (niceSig(sig)+" has a negative expiration interval ("
                 +delta+")\n");
            return false;
        }
        if ((start + delta) <
            (System.currentTimeMillis() - ACCEPTABLE_DELTA_MSEC)) {
            errors.append(niceSig(sig)+" has expired\n");
            return false;
        }
        return true;
    }

    // willing to accept timestamps within this interval. (1 minute)
    private final static long ACCEPTABLE_DELTA_MSEC = 60l*1000l;
}
