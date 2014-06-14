##OpenPGP test suite

This is a little set of tests to how your implementation handles
[OpenPGP](http://tools.ietf.org/html/rfc4880 "OpenPGP RFC"). It is the
result of poking with a few implementations and being surprised at
some of the mistakes in them.

I've tried to find a few basic tests that expose potential security
issues if handled incorrectly. Of course, this is nowhere close to an
exhaustive test, but do hope you find them useful in reducing such
problems in your own implementation.

Please do suggest additional test cases - a pull request with new
tests would be awesome.

##Test format

The test cases are under the `tests` directory, and each test has its
own subdirectory. Within each test is a `README` file which explains
how to run the test, and the expected results. I'm afraid I didn't
have a more programmatic way describe these tests, but this seemed
like the easiest way to get started.
