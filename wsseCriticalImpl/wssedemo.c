/*
        wssedemo.c

        WS-Security plugin demo application. See comments below.

gSOAP XML Web services tools
Copyright (C) 2000-2018, Robert van Engelen, Genivia Inc., All Rights Reserved.
This part of the software is released under one of the following licenses:
GPL or Genivia's license for commercial use.
--------------------------------------------------------------------------------
GPL license.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place, Suite 330, Boston, MA 02111-1307 USA

Author contact information:
engelen@genivia.com / engelen@acm.org
--------------------------------------------------------------------------------
A commercial use license is available from Genivia, Inc., contact@genivia.com
--------------------------------------------------------------------------------

This application demonstrates the use of the wsse plugin.

Compile in C:

soapcpp2 -c -I import wssedemo.h
cc -DWITH_OPENSSL -DWITH_DOM -o wssedemo wssedemo.c wsseapi.c smdevp.c mecevp.c dom.c stdsoap2.c soapC.c soapClient.c soapServer.c -lcrypto -lssl

Compile in C++ (assuming .c files treated as .cpp files):

soapcpp2 -I import wssedemo.h
c++ -DWITH_OPENSSL -DWITH_DOM -o wssedemo wssedemo.c wsseapi.c smdevp.c mecevp.c dom.cpp stdsoap2.cpp soapC.cpp soapClient.cpp soapServer.cpp -lcrypto -lssl

Other required files:

server.pem              server private key and certificate (do not distrubute)
servercert.pem          server public certificate for public distribution
cacert.pem              root CA certificate for public distribution

Notes:

The wsse.h, wsu.h, ds.h, xenc.h c14n.h files are located in 'import'.
The smdevp.*, mecevp.* and wsseapi.* files are located in 'plugin'.

This demo uses SHA1 as an example, which is chosen to ensure that OpenSSL 0.9.7
and earlier can handle the signed messages.  Recommended is SHA256 or greater.
Just change SOAP_XYZ_SHA1 to SOAP_XYZ_SHA256 in the source code below, except
in the token_handler() function.

Usage: wssedemo abcdefghiklmnopqstxyz [port]

with options:

a sign the ns1:add operation in the SOAP Body (use option b to remove Body sig)
b don't sign the entire SOAP Body (signed by default)
c enable chunked HTTP
d use triple DES secret key for encryption instead of RSA
e encrypt the SOAP Body only
f encrypt the signature and the <ns1:add> operation in the Body, rather than entire SOAP Body
g sign parts instead of the entire SOAP Body
h use hmac shared secret key for digital signatures instead of RSA keys
i indent XML
k don't put signature keys in the WS-Security header
l inclusive canonicalization (when used with 'n')
m use GCM with AES
n canonicalize XML (exclusive C14N, recommended!)
o use rsa-oaep-mgf1p with AES256 CBC
p add prefixlist for c14n:InclusiveNamespaces/PrefixList for canonical XML interop
q add prefixlist for c14n:InclusiveNamespaces/PrefixList with all namespace prefixes to thwart attacks on prefix bindings
s server (stand-alone)
t use plain-text passwords (password digest by default)
u use MTOM format with one MIME attachment
x use plain XML (no HTTP header), client only
y buffered sends (experimental, disabled - not critical to use)
z enable compression

For example, to generate a request message and store it in file 'wssedemo.xml':

./wssedemo n > wssedemo.xml < /dev/null

To parse and verify this request message:

./wssedemo ns < wssedemo.xml

Alternatively, using HMAC (fast but uses shared symmetric keys):

./wssedemo hn > wssedemo.xml < /dev/null
./wssedemo hns < wssedemo.xml

To run a stand-alone server:

./wssedemo ns 8080

And invoking it with a client:

./wssedemo n 8080

To test multiple calls using HTTP keep-alive, add a single digit number of runs
at the end of the options:

./wssedemo n4 8080

*/

#include "wsseapi.h"
#include "wssetest.nsmap"

/* The client and server side use the same certificates and keys for demonstration purposes */
X509 *cert = NULL;
EVP_PKEY *rsa_privk = NULL, *rsa_pubk = NULL;

/* The secret HMAC key is shared between client and server */
static char hmac_key[16] = /* Dummy HMAC key for signature test */
{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

/* The WS-SecureConversation Context Token ID we pick for the HMAC key, here we use a fake one to demo */
const char *contextId = "uuid:secure-conversation-context-token"; 

/* The secret triple DES key shared between client and server for message encryption */
static char des_key[20] = /* Dummy 160-bit triple DES key for encryption test */
{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

/* The secret AES key shared between client and server for message encryption */
static char aes_key[32] = /* Dummy 256-bit AES256 key for encryption test */
{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

int addsig = 0;
int addenc = 0;
int nobody = 0; /* do not sign the SOAP Body */
int hmac = 0;   /* symmetric signature */
int nokey = 0;  /* do not include signer's public key in message */
int nohttp = 0;
int sym = 0;    /* symmetric encryption */
int enc = 0;    /* encryption */
int oaep = 0;   /* use Rsa-oaep-mgf1p with AES256 CBC */
int aes = 0;    /* use AES256 instead of DES */
int gcm = 0;    /* use AES with GCM instead of CBC mode (requires OpenSSL 1.0.2) */
int mtom = 0;   /* use MTOM format with attachment (not signed or encrypted) */

/** Optional user-defined key lookup function, see WSSE docs */
static const void *token_handler(struct soap *soap, int *alg, const char *keyname, const unsigned char *keyid, int keyidlen, int *keylen)
{
  const char *ctxId;
  /* we're not using keyname or other info, which is from the ds:KeyInfo/KeyName content */
  (void)keyname;
  (void)keyid;
  (void)keyidlen;
  switch (*alg)
  {
    case SOAP_SMD_VRFY_DSA_SHA1:
    case SOAP_SMD_VRFY_DSA_SHA256:
    case SOAP_SMD_VRFY_RSA_SHA1:
    case SOAP_SMD_VRFY_RSA_SHA224:
    case SOAP_SMD_VRFY_RSA_SHA256:
    case SOAP_SMD_VRFY_RSA_SHA384:
    case SOAP_SMD_VRFY_RSA_SHA512:
    case SOAP_SMD_VRFY_ECDSA_SHA1:
    case SOAP_SMD_VRFY_ECDSA_SHA224:
    case SOAP_SMD_VRFY_ECDSA_SHA256:
    case SOAP_SMD_VRFY_ECDSA_SHA384:
    case SOAP_SMD_VRFY_ECDSA_SHA512:
      return (const void*)cert; /* signature verification with public cert */
    case SOAP_SMD_HMAC_SHA1:
      /* Optional: WS-SecureConversation: get & check context token ID of HMAC key */
      ctxId = soap_wsse_get_SecurityContextToken(soap);
      if (!ctxId || strcmp(ctxId, contextId))
        return NULL;
      *keylen = sizeof(hmac_key);
      return (const void*)hmac_key; /* signature verification with secret key */
    case SOAP_MEC_ENV_DEC_DES_CBC:
    case SOAP_MEC_ENV_DEC_AES256_CBC:
    case SOAP_MEC_ENV_DEC_AES256_GCM:
      if (keyname)
      { /* use this to get private key from one of these keyname values:
           1. keyname is set to the subject name of the certificate, if a
              certificate is present in the SecurityTokenReference/KeyIdentifier
              when ValueType is http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3
           2. keyname is set to the string concatenation of
               "{X509IssuerName}#{X509SerialNumber}" of the X509IssuerName
               and X509SerialNumber present in X509Data/X509IssuerSerial
           3. keyname is set to X509Data/X509SubjectName
         */
      }
      else if (keyid)
      { /* use this to get private key from:
           1. keyid and keyidlen are set to the data in
              SecurityTokenReference/KeyIdentifier when the ValueType is
              http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier
         */
      }
      return (const void*)rsa_privk; /* envelope decryption with private key */
    case SOAP_MEC_DEC_DES_CBC:
      /* should inquire keyname (contains key name or subject name/key id) */
      *keylen = sizeof(des_key);
      return (const void*)des_key; /* decryption with secret key */
    case SOAP_MEC_DEC_AES256_CBC:
    case SOAP_MEC_DEC_AES256_GCM:
      /* should inquire keyname (contains key name or subject name/key id) */
      *keylen = sizeof(aes_key);
      return (const void*)aes_key; /* decryption with secret key */
  }
  fprintf(stderr, "Could not return a key from token handler for '%s'\n", keyname ? keyname : "");
  return NULL; /* fail */
}

/* server-side settings before soap_serve() to verify signatures and decrypt messages */
static int set_verify_decrypt_auto(struct soap *soap)
{
  int err;

  /* auto-verify signature options */
  if (hmac)
    err = soap_wsse_verify_auto(soap, SOAP_SMD_HMAC_SHA1, (void*)hmac_key, sizeof(hmac_key));
  else if (nokey)
    err = soap_wsse_verify_auto(soap, SOAP_SMD_VRFY_RSA_SHA1, (void*)rsa_pubk, 0);
  else
    err = soap_wsse_verify_auto(soap, SOAP_SMD_NONE, NULL, 0);
  if (err)
    return soap->error;

  /* auto-decrypt options */
  if (sym)
  {
    if (aes)
    {
      if (gcm)
	err = soap_wsse_decrypt_auto(soap, SOAP_MEC_DEC_AES256_GCM, aes_key, sizeof(aes_key));
      else
	err = soap_wsse_decrypt_auto(soap, SOAP_MEC_DEC_AES256_CBC, aes_key, sizeof(aes_key));
    }
    else
      err = soap_wsse_decrypt_auto(soap, SOAP_MEC_DEC_DES_CBC, des_key, sizeof(des_key));
  }
  else if (enc)
    err = soap_wsse_decrypt_auto(soap, SOAP_MEC_ENV_DEC_DES_CBC, rsa_privk, 0);
  return err;
}

int main(int argc, char **argv)
{
  struct soap *soap;
  int server = 0;
  int text = 0;
  int port = 0;
  FILE *fd;
  double result;
  char *user;
  int runs = 1;

  /* create context */
  soap = soap_new();
  /* register wsse plugin and set the optional security token handler callback */
  soap_register_plugin(soap, soap_wsse);
  soap_wsse_set_security_token_handler(soap, token_handler);

  /* options */
  if (argc >= 2)
  {
    if (strchr(argv[1], 'c'))
      soap_set_omode(soap, SOAP_IO_CHUNK);
    else if (strchr(argv[1], 'y'))
      soap_set_omode(soap, SOAP_IO_STORE);
    if (strchr(argv[1], 'i'))
      soap_set_omode(soap, SOAP_XML_INDENT);
    if (strchr(argv[1], 'n'))
      soap_set_omode(soap, SOAP_XML_CANONICAL);
    if (strchr(argv[1], 'p'))
      soap_wsse_set_InclusiveNamespaces(soap, "ns1");
    if (strchr(argv[1], 'q'))
      soap_wsse_set_InclusiveNamespaces(soap, "+");
    if (strchr(argv[1], 'l'))
      soap_wsse_set_InclusiveNamespaces(soap, "*");
    if (strchr(argv[1], 'a'))
      aes = 1;
    if (strchr(argv[1], 'm'))
      gcm = 1;
    if (strchr(argv[1], 'o'))
      oaep = 1;
    if (strchr(argv[1], 'd'))
      sym = 1;
    if (strchr(argv[1], 'e'))
      enc = 1;
    if (strchr(argv[1], 'f'))
      addenc = 1;
    if (strchr(argv[1], 'h'))
      hmac = 1;
    if (strchr(argv[1], 'k'))
      nokey = 1;
    if (strchr(argv[1], 's'))
      server = 1;
    if (strchr(argv[1], 't'))
      text = 1;
    if (strchr(argv[1], 'g'))
      addsig = 1;
    if (strchr(argv[1], 'b'))
      nobody = 1;
    if (strchr(argv[1], 'u'))
    {
      soap_set_omode(soap, SOAP_ENC_MTOM | SOAP_ENC_DIME); /* this forces MTOM attachment format, to test */
      mtom = 1;
    }
    if (strchr(argv[1], 'x'))
      nohttp = 1;
    if (strchr(argv[1], 'z'))
      soap_set_mode(soap, SOAP_ENC_ZLIB);
    if (isdigit(argv[1][strlen(argv[1])-1]))
    {
      runs = argv[1][strlen(argv[1])-1] - '0';
      soap_set_mode(soap, SOAP_IO_KEEPALIVE);
    }
  }

  /* soap->actor = "..."; */ /* set only when required by peer */
  user = getenv("USER");
  if (!user)
    user = (char*)"anyone";

  /* read RSA private key for signing */
  if ((fd = fopen("server.pem", "r")))
  {
    rsa_privk = PEM_read_PrivateKey(fd, NULL, NULL, (void*)"password");
    fclose(fd);
    if (!rsa_privk)
    {
      fprintf(stderr, "Could not read private RSA key from server.pem\n");
      exit(1);
    }
  }
  else
  {
    fprintf(stderr, "Could not read server.pem\n");
    exit(1);
  }

  /* read certificate (more efficient is to keep certificate in memory)
     to obtain public key for encryption and signature verification */
  if ((fd = fopen("servercert.pem", "r")))
  {
    cert = PEM_read_X509(fd, NULL, NULL, NULL);
    fclose(fd);
    if (!cert)
    {
      fprintf(stderr, "Could not read certificate from servercert.pem\n");
      exit(1);
    }
  }
  else
  {
    fprintf(stderr, "Could not read servercert.pem\n");
    exit(1);
  }

  rsa_pubk = X509_get_pubkey(cert);
  if (!rsa_pubk)
  {
    fprintf(stderr, "Could not get public key from certificate\n");
    exit(1);
  }

  /* port argument */
  if (argc >= 3)
    port = atoi(argv[2]);

  /* need cacert to verify certificates with CA (cacert.pem for testing and
     cacerts.pem for production, which contains the trusted CA certificates) */
  soap->cafile = "cacert.pem";

  /* server / */
  if (server)
  {
    if (port)
    {
      /* stand-alone server serving messages over port */
      if (!soap_valid_socket(soap_bind(soap, NULL, port, 100)))
      {
        soap_print_fault(soap, stderr);
        exit(1);
      }
      printf("Server started at port %d\n", port);
      /* HTTP keep-alive is not trivial to support because we need to set soap_wsse_verify_auto and soap_wsse_decrypt_auto */
      if (soap->mode & SOAP_IO_KEEPALIVE)
      {
	/* set the serverloop callback to call soap_wsse_verify_auto and soap_wsse_decrypt_auto etc. for each next iteration */
	soap->fserveloop = set_verify_decrypt_auto;
      }
      while (soap_valid_socket(soap_accept(soap)))
      {
        fprintf(stderr, "Accepting connection from IP %d.%d.%d.%d\n", (int)(soap->ip>>24)&0xFF, (int)(soap->ip>>16)&0xFF, (int)(soap->ip>>8)&0xFF, (int)soap->ip&0xFF);

	if (set_verify_decrypt_auto(soap)
         || soap_serve(soap))
        {
          soap_wsse_delete_Security(soap);
          soap_print_fault(soap, stderr);
          soap_print_fault_location(soap, stderr);
        }
        soap_destroy(soap);
        soap_end(soap);
      }
      soap_print_fault(soap, stderr);
      exit(1);
    }
    else /* CGI-style server serving messages over stdin/out */
    {
      if (set_verify_decrypt_auto(soap)
       || soap_serve(soap))
      {
        soap_wsse_delete_Security(soap);
        soap_print_fault(soap, stderr);
        soap_print_fault_location(soap, stderr);
        exit(1);
      }
      soap_destroy(soap);
      soap_end(soap);
    }
  }
  else /* client */
  {
    int run;
    char endpoint[80];

    /* client sends messages to stdout or to a server port */
    if (port)
      (SOAP_SNPRINTF(endpoint, sizeof(endpoint), 37), "http://localhost:%d", port);
    else if (nohttp)
      soap_strcpy(endpoint, sizeof(endpoint), "");
    else
      soap_strcpy(endpoint, sizeof(endpoint), "http://");

    /* run */
    for (run = 0; run < runs; run++)
    {
      /* message lifetime of 60 seconds */
      soap_wsse_add_Timestamp(soap, "Time", 60);

      /* add user name with text password (unsafe unless over HTTPS) or digest password */
      if (text)
	soap_wsse_add_UsernameTokenText(soap, "User", user, "userPass");
      else
	soap_wsse_add_UsernameTokenDigest(soap, "User", user, "userPass");

      /* symmetric encryption option */
      if (sym)
      {
	if (aes)
	{
	  /* symmetric encryption with AES CBC/GCM */
	  soap_wsse_add_EncryptedData_KeyInfo_KeyName(soap, "My AES Key");
	  if (gcm)
	  {
	    if (soap_wsse_encrypt_body(soap, SOAP_MEC_ENC_AES256_GCM, aes_key, sizeof(aes_key)))
	      soap_print_fault(soap, stderr);
	    soap_wsse_decrypt_auto(soap, SOAP_MEC_DEC_AES256_GCM, aes_key, sizeof(aes_key));
	  }
	  else
	  {
	    if (soap_wsse_encrypt_body(soap, SOAP_MEC_ENC_AES256_CBC, aes_key, sizeof(aes_key)))
	      soap_print_fault(soap, stderr);
	    soap_wsse_decrypt_auto(soap, SOAP_MEC_DEC_AES256_CBC, aes_key, sizeof(aes_key));
	  }
	}
	else
	{
	  /* symmetric encryption with DES */
	  soap_wsse_add_EncryptedData_KeyInfo_KeyName(soap, "My DES Key");
	  if (soap_wsse_encrypt_body(soap, SOAP_MEC_ENC_DES_CBC, des_key, sizeof(des_key)))
	    soap_print_fault(soap, stderr);
	  soap_wsse_decrypt_auto(soap, SOAP_MEC_DEC_DES_CBC, des_key, sizeof(des_key));
	}
      }
      else if (addenc) /* RSA encryption option of specific XML element */
      {
	/* RSA encryption of the <ns1:add> element option */
	const char *SubjectKeyId = NULL; /* set to non-NULL to use SubjectKeyIdentifier in Header rather than a full cert key */
	/* MUST set wsu:Id of the elements to encrypt */
	soap_wsse_set_wsu_id(soap, "ns1:add");
	if (soap_wsse_add_EncryptedKey_encrypt_only(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, SubjectKeyId, NULL, NULL, "ds:Signature ns1:add"))
	  soap_print_fault(soap, stderr);
	soap_wsse_decrypt_auto(soap, SOAP_MEC_ENV_DEC_DES_CBC, rsa_privk, 0);
      }
      else if (enc) /* RSA encryption of the SOAP Body option */
      {
	const char *SubjectKeyId = NULL; /* set to non-NULL to use SubjectKeyIdentifier in Header rather than a full cert key */
	if (oaep)
	{
	  if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_AES256_CBC | SOAP_MEC_OAEP, "Cert", cert, SubjectKeyId, NULL, NULL))
	    soap_print_fault(soap, stderr);
	}
	else if (aes)
	{
	  if (gcm)
	  {
	    if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_AES256_GCM, "Cert", cert, SubjectKeyId, NULL, NULL))
	      soap_print_fault(soap, stderr);
	  }
	  else
	  {
	    if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_AES256_CBC, "Cert", cert, SubjectKeyId, NULL, NULL))
	      soap_print_fault(soap, stderr);
	  }
	}
	else
	{
          
	  if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, SubjectKeyId, NULL, NULL))
	    soap_print_fault(soap, stderr);
	}
	soap_wsse_decrypt_auto(soap, SOAP_MEC_ENV_DEC_DES_CBC, rsa_privk, 0);
      }

      /* HMAC signature */
      if (hmac)
      {
	if (nobody)
	  soap_wsse_sign(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key));
	else
	  soap_wsse_sign_body(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key));
	/* WS-SecureConversation contect token */
	soap_wsse_add_SecurityContextToken(soap, "SCT", contextId);
      }
      else /* RSA signature verification */
      {
	if (nokey)
	  soap_wsse_add_KeyInfo_KeyName(soap, "MyKey");
	else
	{
	  soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert);
	  soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token");
	}
	if (nobody || addsig) /* do not sign body */
	  soap_wsse_sign(soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_privk, 0);
	else
	  soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_privk, 0);
      }

      /* auto-verification of signatures in server responses */
      if (hmac)
	soap_wsse_verify_auto(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key));
      else if (nokey)
	soap_wsse_verify_auto(soap, SOAP_SMD_VRFY_RSA_SHA1, rsa_pubk, 0);
      else
	soap_wsse_verify_auto(soap, SOAP_SMD_NONE, NULL, 0);

      /* sign message parts inside unsigned body? If so, set wsu:Id of those */
      if (addsig)
      {
	soap_wsse_set_wsu_id(soap, "ns1:add");
        /* Edit #1 - removed x509 from sign*/
        /* should sign the timestamp, usernameToken, certificate, and ns1:add */
	soap_wsse_sign_only(soap, "Time User ns1:add");
      }

      /* optionally use mtom attachments, which are not signed or encypted, here we add a simple message */
      if (mtom)
        soap_set_mime_attachment(soap, "Hello World", 11, SOAP_MIME_NONE, "text/text", "ID", "location", "description");

      /* invoke the server. You can choose add, sub, mul, or div operations
       * that show different security aspects (intentional message rejections)
       * for demonstration purposes (see server operations below) */
      if (!soap_call_ns1__add(soap, endpoint, NULL, 1.0, 2.0, &result))
      {
	if (!soap_wsse_verify_Timestamp(soap))
	{
	  const char *servername = soap_wsse_get_Username(soap);
	  if (servername
	      && !strcmp(servername, "server")
	      && !soap_wsse_verify_Password(soap, "serverPass"))
	    fprintf(stderr, "Result = %g\n", result);
	  else
	  {
	    fprintf(stderr, "Server authentication failed\n");
	    soap_print_fault(soap, stderr);
	  }
	}
	else
	{
	  fprintf(stderr, "Server response expired\n");
	  soap_print_fault(soap, stderr);
	}
      }
      else
      {
	soap_print_fault(soap, stderr);
	soap_print_fault_location(soap, stderr);
	if (soap->error != SOAP_EOF)
	  exit(1);
      }
      /* clean up security header */
      soap_wsse_delete_Security(soap);
      /* disable soap_wsse_verify_auto */
      soap_wsse_verify_done(soap);

    } /* run */

  }
  /* clean up keys */
  if (rsa_privk)
    EVP_PKEY_free(rsa_privk);
  if (rsa_pubk)
    EVP_PKEY_free(rsa_pubk);
  if (cert)
    X509_free(cert);
  /* clean up gSOAP engine */
  soap_destroy(soap);
  soap_end(soap);
  soap_done(soap);
  free(soap);
  /* done */
  return 0;
}

int ns1__add(struct soap *soap, double a, double b, double *result)
{
  const char *username = soap_wsse_get_Username(soap);
  /* Edit #2 - Should use received cert to encrypt response */
  X509 *cert2 = soap_wsse_get_BinarySecurityTokenX509(soap, "X509Token");
  if (username)
    fprintf(stderr, "Hello %s, want to add %g + %g = ?\n", username, a, b);
  if (soap_wsse_verify_Timestamp(soap)
   || soap_wsse_verify_Password(soap, "userPass"))
  {
    int err = soap->error; /* preserve error code */
    soap_wsse_delete_Security(soap); /* remove WS-Security information */
    /* the above suffices to return an unsigned fault, but here we show how to return a signed fault: */
    soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert);
    soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token");
    soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_privk, 0);
    return err;
  }
  if (soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Timestamp") == 0
   || soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "UsernameToken") == 0)
  {
    soap_wsse_delete_Security(soap);
    return soap_sender_fault(soap, "Timestamp and/or usernameToken not signed", NULL);
  }
  if (soap_wsse_verify_element(soap, "http://www.genivia.com/schemas/wssetest.xsd", "add") == 0)
  {
    soap_wsse_delete_Security(soap);
    return soap_sender_fault(soap, "Service operation not signed", NULL);
  }
  soap_wsse_delete_Security(soap); /* remove WS-Security before setting new security information */
  soap_wsse_add_Timestamp(soap, "Time", 10);    /* lifetime of 10 seconds */
  soap_wsse_add_UsernameTokenDigest(soap, "User", "server", "serverPass");
  if (hmac)
  {
    if (nobody || addsig)
      soap_wsse_sign(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key));
    else
      soap_wsse_sign_body(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key));
    /* WS-SecureConversation context token */
    soap_wsse_add_SecurityContextToken(soap, "SCT", contextId);
  }
  else
  {
    if (nokey)
      soap_wsse_add_KeyInfo_KeyName(soap, "MyKey");
    else
    {
      soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert);
      soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token");
    }
    if (nobody || addsig)
      soap_wsse_sign(soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_privk, 0);
    else
      soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_privk, 0);
  }
  /* sign the response message inside the unsigned enveloping body? If so, set wsu:Id of the response */
  if (addsig)
    soap_wsse_set_wsu_id(soap, "ns1:addResponse");
  if (sym)
  {
    if (aes)
    {
      soap_wsse_add_EncryptedData_KeyInfo_KeyName(soap, "My AES Key");
      if (gcm)
      {
        if (soap_wsse_encrypt_body(soap, SOAP_MEC_ENC_AES256_GCM, aes_key, sizeof(aes_key)))
          soap_print_fault(soap, stderr);
      }
      else
      {
        if (soap_wsse_encrypt_body(soap, SOAP_MEC_ENC_AES256_CBC, aes_key, sizeof(aes_key)))
          soap_print_fault(soap, stderr);
      }
    }
    else
    {
      soap_wsse_add_EncryptedData_KeyInfo_KeyName(soap, "My DES Key");
      if (soap_wsse_encrypt_body(soap, SOAP_MEC_ENC_DES_CBC, des_key, sizeof(des_key)))
        soap_print_fault(soap, stderr);
    }
  }
  else if (addenc)
  {
    /* MUST set wsu:Id of the elements to encrypt */
    soap_wsse_set_wsu_id(soap, "ns1:addResponse");
    if (soap_wsse_add_EncryptedKey_encrypt_only(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert, NULL, NULL, NULL, "ds:Signature ns1:addResponse"))
      soap_print_fault(soap, stderr);
  }
  else if (enc)
  {
    if (oaep)
    {
      if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_AES256_CBC | SOAP_MEC_OAEP, "Cert", cert2, NULL, NULL, NULL))
        soap_print_fault(soap, stderr);
    }
    else if (aes)
    {
      if (gcm)
      {
        if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_AES256_GCM, "Cert", cert2, NULL, NULL, NULL))
          soap_print_fault(soap, stderr);
      }
      else
      {
        if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_AES256_CBC, "Cert", cert2, NULL, NULL, NULL))
          soap_print_fault(soap, stderr);
      }
    }
    else
    {
      if (soap_wsse_add_EncryptedKey(soap, SOAP_MEC_ENV_ENC_DES_CBC, "Cert", cert2, NULL, NULL, NULL))
        soap_print_fault(soap, stderr);
    }
    X509_free(cert2);
  }
  *result = a + b;
  return SOAP_OK;
}

int ns1__sub(struct soap *soap, double a, double b, double *result)
{
  const char *username = soap_wsse_get_Username(soap);
  if (username)
    fprintf(stderr, "Hello %s, want to subtract %g - %g = ?\n", username, a, b);
  if (soap_wsse_verify_Timestamp(soap)
   || soap_wsse_verify_Password(soap, "userPass"))
  {
    soap_wsse_delete_Security(soap);
    return soap->error;
  }
  if (soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Timestamp") == 0
   || soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "UsernameToken") == 0)
  {
    soap_wsse_delete_Security(soap);
    return soap_sender_fault(soap, "Timestamp and/or usernameToken not signed", NULL);
  }
  if (soap_wsse_verify_element(soap, "http://www.genivia.com/schemas/wssetest.xsd", "sub") == 0)
  {
    soap_wsse_delete_Security(soap);
    return soap_sender_fault(soap, "Service operation not signed", NULL);
  }
  soap_wsse_delete_Security(soap);
  /* In this case we leave out the timestamp, which is the sender's
   * responsibility to add. The receiver only complains if the timestamp is out
   * of date, not that it is absent. */
  if (hmac)
  {
    soap_wsse_sign_body(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key));
    /* WS-SecureConversation contect token */
    soap_wsse_add_SecurityContextToken(soap, "SCT", contextId);
  }
  else
  {
    if (nokey)
      soap_wsse_add_KeyInfo_KeyName(soap, "MyKey");
    else
    {
      soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert);
      soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token");
    }
    soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_privk, 0);
  }
  *result = a - b;
  return SOAP_OK;
}

int ns1__mul(struct soap *soap, double a, double b, double *result)
{
  const char *username = soap_wsse_get_Username(soap);
  if (username)
    fprintf(stderr, "Hello %s, want to multiply %g * %g = ?\n", username, a, b);
  if (soap_wsse_verify_Timestamp(soap)
   || soap_wsse_verify_Password(soap, "userPass"))
  {
    soap_wsse_delete_Security(soap);
    return soap->error;
  }
  if (soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Timestamp") == 0
   || soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "UsernameToken") == 0)
  {
    soap_wsse_delete_Security(soap);
    return soap_sender_fault(soap, "Timestamp and/or usernameToken not signed", NULL);
  }
  if (soap_wsse_verify_element(soap, "http://www.genivia.com/schemas/wssetest.xsd", "mul") == 0)
  {
    soap_wsse_delete_Security(soap);
    return soap_sender_fault(soap, "Service operation not signed", NULL);
  }
  soap_wsse_delete_Security(soap);
  soap_wsse_add_Timestamp(soap, "Time", 10);    /* lifetime of 10 seconds */
  /* In this case we leave out the server name and password. Because the
   * client receiver requires the presence of authentication information, the
   * client will reject the response. */
  if (hmac)
  {
    soap_wsse_sign_body(soap, SOAP_SMD_HMAC_SHA1, hmac_key, sizeof(hmac_key));
    /* WS-SecureConversation contect token */
    soap_wsse_add_SecurityContextToken(soap, "SCT", contextId);
  }
  else
  {
    if (nokey)
      soap_wsse_add_KeyInfo_KeyName(soap, "MyKey");
    else
    {
      soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert);
      soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token");
    }
    soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA1, rsa_privk, 0);
  }
  *result = a * b;
  return SOAP_OK;
}

int ns1__div(struct soap *soap, double a, double b, double *result)
{
  const char *username = soap_wsse_get_Username(soap);
  if (username)
    fprintf(stderr, "Hello %s, want to divide %g / %g = ?\n", username, a, b);
  if (soap_wsse_verify_Timestamp(soap)
   || soap_wsse_verify_Password(soap, "userPass"))
  {
    soap_wsse_delete_Security(soap);
    return soap->error;
  }
  if (soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Timestamp") == 0
   || soap_wsse_verify_element(soap, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "UsernameToken") == 0)
  {
    soap_wsse_delete_Security(soap);
    return soap_sender_fault(soap, "Timestamp and/or usernameToken not signed", NULL);
  }
  if (soap_wsse_verify_element(soap, "http://www.genivia.com/schemas/wssetest.xsd", "div") == 0)
  {
    soap_wsse_delete_Security(soap);
    return soap_sender_fault(soap, "Service operation not signed", NULL);
  }
  soap_wsse_delete_Security(soap);
  soap_wsse_add_Timestamp(soap, "Time", 10);    /* lifetime of 10 seconds */
  soap_wsse_add_UsernameTokenDigest(soap, "User", "server", "serverPass");
  /* In this case we leave out the signature and the receiver will reject this unsigned message. */
  if (b == 0.0)
    return soap_sender_fault(soap, "Division by zero", NULL);
  *result = a / b;
  return SOAP_OK;
}
