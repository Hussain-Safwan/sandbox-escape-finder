import base64

payload = b"X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2lkJyk="
exec(base64.b64decode(payload))