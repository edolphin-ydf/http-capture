
# Usage

1. Generate your self-signed certificate

```bash
openssl genrsa -out demo.key 2048
openssl req -new -x509 -key mykey.key -out mycert.crt -days 3650 -addext subjectAltName=DNS:<hostname>,IP:<ip>
```

2. Create your customized capture.yaml.

3. Build and start capture
