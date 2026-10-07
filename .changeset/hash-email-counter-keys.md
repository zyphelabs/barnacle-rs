---
default: patch
---

Hash email addresses in counter keys and redact them in logs

`BarnacleKey::Email` counters are now stored under the SHA-256 of the address
(`barnacle:email:<sha256>:<method>:<path>`), as API keys already were, and `BarnacleKey`'s `Debug`
output redacts the address. Upgrading resets the email counters once: their old clear-text keys are
no longer read and expire with their window.
