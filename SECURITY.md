# Security policy

## Supported versions

Security fixes are released for the latest minor version of mifarepy.

| Version | Supported |
|---|---|
| 3.x (latest) | ✅ |
| < 3.0 | ❌ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through GitHub:
[**Report a vulnerability**](https://github.com/SparkDrago05/mifarepy/security/advisories/new).
Alternatively, email **huzaifa.farooq05@gmail.com** with "mifarepy security" in the subject.

Please include:

- the mifarepy version and Python version,
- the reader model and firmware (`reader.get_version()`), if relevant,
- steps to reproduce and the impact you expect.

You can expect an acknowledgement within **3 working days** and a status update
within **10 working days**. Once a fix is released we will credit you in the
changelog and the advisory, unless you prefer to stay anonymous.

## Scope

In scope: bugs in mifarepy that could, for example, leak keys (such as logging
them), write to the wrong block or sector, corrupt value blocks, or crash a
host application on malformed reader input.

Out of scope: the known cryptographic weaknesses of MIFARE Classic (Crypto1)
itself. See the
[security notes](https://sparkdrago05.github.io/mifarepy/latest/mifare-classic/#security-notes)
in the documentation for guidance on deploying Classic cards safely.
