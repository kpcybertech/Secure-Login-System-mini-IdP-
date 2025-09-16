import sys, inspect
import jwt

print("exe:", sys.executable)
print("jwt from:", getattr(jwt, "__file__", "UNKNOWN"))
print("has encode:", hasattr(jwt, "encode"))

try:
    tok = jwt.encode({"k":"v"}, "secret", algorithm="HS256")
    print("encode ok, token prefix:", str(tok)[:20])
except Exception as e:
    print("encode failed:", repr(e))