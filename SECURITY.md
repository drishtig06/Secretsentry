# Security policy

SecretSentry scans files locally and does not make network requests. Findings and JSON reports contain redacted values, but file paths, line numbers, rule names, and partial secret fragments may still be sensitive. Store reports securely and do not publish them without review.

SecretSentry is an educational, lightweight detector—not a replacement for mature secret-scanning tools or a guarantee that a repository is clean. Detection uses patterns and can produce false positives or miss secrets. Rotate any credential that may have been exposed, even if a scanner reports it as fixed.

To report a vulnerability, use GitHub's private vulnerability reporting for this repository when enabled. Do not open a public issue containing a real secret or exploit details.
