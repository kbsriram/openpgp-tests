If you use the [bouncycastle java
library](https://www.bouncycastle.org/java.html), you may be aware
that the library itself does no validation of public key rings - it
expects you to validate keys within your application.

I hope you find the code here useful to add some basic validation on
public key rings. I don't claim it is complete by any means, but do
hope you find it adds some important checks that can be tedious to
implement using the OpenPGP support from bouncycastle.

There's just one file of interest,
[CPGPUtils.java](src/com/kbsriram/openpgp/CPGPUtils.java). Use it by
passing in a `PGPPublicKeyRing` through its static `validate`
method. It returns an instance of `CPGPUtils.PKR`, which is an object
that provides access to verified userids, attributes, and subkeys. If
there were partial errors, they are logged and available through the
`getErrors()` method.

It also takes in an optional `CPGPUtils.KeyFinder` instance. It is
used to fetch related public keys -- for instance, public keys for
signatures signed by other people in PGP's web-of-trust model. You can
also pass in a `null`, and the code will just reject all such
signatures.

Finally - the bouncycastle APIs tend to be somewhat of a moving
target. The code was written against the 1.50 version of the library,
and I've placed these jar files directly in this repository.
