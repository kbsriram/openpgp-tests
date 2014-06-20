##OpenPGP test suite

This is a little set of tests to see how your implementation handles
[OpenPGP](http://tools.ietf.org/html/rfc4880 "OpenPGP RFC"). It is the
result of poking into a few implementations and realizing that it
would be useful to have a small suite of tests that check if some
basic validations are performed by an implementation that uses
OpenPGP.

I've tried to find tests that expose potential security issues if
handled incorrectly. Of course, this is nowhere close to an exhaustive
test, but do hope you find them useful in reducing such problems in
your own implementation.

I've also created a small validation library if you happen to use the
[bouncycastle java
library](https://www.bouncycastle.org/java.html). Please look within
the [java example](example/java) directory for more information.

Please do suggest additional test cases - a pull request with new
tests would be awesome.

##Test format

The test cases are under the `tests` directory, and each test has its
own subdirectory. Within each test is a `README` file which explains
how to run the test, and the expected results. I'm afraid I didn't
have a more programmatic way describe these tests, but this seemed
like the easiest way to get started.
