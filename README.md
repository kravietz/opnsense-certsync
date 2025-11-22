# OPNsense certificate sync

This program fetches up to date X.509 certificate and private key from OPNsense firewall
with ACME client for synchronisation with local systems. The fetched certificate is then
bundled with the intermediate certificate chain. For now only Let's Encrypt certificates are
supported.

Example usage:

```
env OPNSENSE_KEY=... OPNSENSE_SECRET=... OPNSENSE_API=https://opnsense.home.arpa python3 certsync.py example.com
env OPNSENSE_KEY=... OPNSENSE_SECRET=... OPNSENSE_API=https://opnsense.home.arpa python3 certsync.py example.com ./priv.pem ./bundle.pem
```

The program relies on OPNSense API https://docs.opnsense.org/development/how-tos/api.html
and requires API keys to be configured in OPNsense.

## License

[Big Time Public License v2.0](https://bigtimelicense.com/versions/2.0.2)

Copyright 2025 by [Paweł Krawczyk](https://krvtz.net)
