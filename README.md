# pysake

This is a re-implementation of the SAKE cryptographic library in Python.

Original PoC code was provided to the project by @planiitis from https://github.com/planiitis/medtronic-bt-decrypt. Huge thank you and massive respect!


## Run tests

To test the implementation run the following:

    python -m pysake.session
    python -m pysake.server
    python -m pysake.client

Output will tell if you the tests failed or passed.

You must run the tests from the directory where you cloned this repository to. Alternatively, add the path to that directory to your `PYTHONPATH` environment variable so that you can run from everywhere.
