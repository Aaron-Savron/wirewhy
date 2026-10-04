# Contributing

Use Node 20.3 or newer. Collector tests need Python 3.

```sh
npm ci
npm run check
python3 -B test/collector_test.py
npm run test:package
```

To test a real, isolated NGINX outage on Linux:

```sh
WIREWHY_NGINX_BINARY=/usr/sbin/nginx npm test
```

The test uses temporary config and logs on a loopback port. It does not modify your running NGINX service.

Keep reports useful and concise. New diagnoses need evidence and an actionable next step. Add a regression test for behavior changes; avoid real external services in tests.

For bug reports, include the command, Node version, operating system, and relevant report output. Remove any private data from log excerpts before posting.
