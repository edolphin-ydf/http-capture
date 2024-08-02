
# Usage

1. Generate your self-signed certificate

```bash
openssl genrsa -out demo.key 2048
openssl req -new -x509 -key mykey.key -out mycert.crt -days 3650 -addext subjectAltName=DNS:<hostname>,IP:<ip>
```

2. Create your customized capture.yaml.

3. Build and start

4. Make your proxy point to this capture. eg: localhost:8087

5. Visit the captured web site. And get the captured value by `curl http://localhost:8088/?key=your_key_configed_in_capture_yaml`
