You will need the following python modules:
m2crypto,
signxml,
defusedxml

# Running the POC:

Mitm script
-----
```python3 mitm.py``` or ```python3 mitmOriginalWsse.py```

press enter to start on port 8081 (or specify a different port)

Server
-----
In a second terminal, start the server

```cd wsseCriticalImpl``` or ```cd wsseOriginal```

```./wssedemo sne 8080```

Options:
- s: server
- n: normalized XML
- e: encryption
- ~g: don't sign the X509 cert~

Client
-----
In a third terminal, start the client (connect to the port you started the mitm on, 8081 by default)

```cd wsseCriticalImpl``` or ```cd wsseOriginal```

```./wssedemo ne 8081```

Options:
- n: normalized XML
- e: encryption
- g: ~don't sign the X509 cert~
