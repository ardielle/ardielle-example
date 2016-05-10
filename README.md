# ardielle-example

## An Example API

The [RDL file](https://github.com/ardielle/ardielle-example/tree/master/rdl/contacts.rdl) defines a simple service that
manages Contacts. The types in the RDL are a basic Contact type that consistents of a well-formed string
identifier and a set of string key/value pairs called attributes. 

Of note is that the PUT, POST, and DELETE operations on a Contact resource are protected. The example doesn't
actually enforce the authorization, but just logs what it could enforce. Authentication is based on TLS client
certs signed by a common authority.

## Making a Go server

The source for a Go language based server is [here](https://github.com/ardielle/ardielle-example/blob/master/go/contactsd/main.go).
If you look at the [Makefile](https://github.com/ardielle/ardielle-example/blob/master/Makefile), you can see that it generates
the model and server dispatch and related files into go/src/contacts, and builds against that.

    $ make

This creates test keys and certs, and builds the example server in Go. The resulting executable is in go/bin, and
it can simply be executed (from this directory):

    $ ./go/bin/contactsd
    2016/05/10 11:54:03 Initialized Contacts service at 'https://localhost:4443/example/v1'

In another window, you can test with curl:

    $ curl https://localhost:4443/example/v1
    curl: (60) SSL certificate problem: Invalid certificate chain
    More details here: http://curl.haxx.se/docs/sslcerts.html
    
    curl performs SSL certificate verification by default, using a "bundle"
     of Certificate Authority (CA) public keys (CA certs). If the default
     bundle file isn't adequate, you can specify an alternate file
     using the --cacert option.
    If this HTTPS server uses a certificate signed by a CA represented in
     the bundle, the certificate verification probably failed due to a
      problem with the certificate (it might be expired, or the name might
       not match the domain name in the URL).
    If you'd like to turn off curl's verification of the certificate, use
     the -k (or --insecure) option.

Ok, so let's specify our CA cert to avoid that:

    modernthis-lm 11:53:46 ~/ardielle/ardielle-example $ curl --cacert certs/ca.cert https://localhost:4443/example/v1
    {
      "code": 404,
      "message": "Not Found"
    }

So, even though the API endpoint was not defined, we are connecting to it correctly with TLS, and the server's cert
verifies against the CA cert we've defined. Try the listing API point:

    $ curl --cacert certs/ca.cert https://localhost:4443/example/v1/contacts
    {
      "contacts": [
        {
          "id": "boynton",
          "modified": "2016-05-10T18:54:03.083Z",
          "attributes": [
            {
              "label": "email",
              "value": "boynton@yahoo-inc.com"
            }
          ]
        }
      ]
    }

To get a specific contact:

    $ curl --cacert certs/ca.cert https://localhost:4443/example/v1/contacts/boynton
    {
      "id": "boynton",
      "modified": "2016-05-10T18:54:03.083Z",
      "attributes": [
        {
          "label": "email",
          "value": "boynton@yahoo-inc.com"
        }
      ]
    }

Now try to delete that:

    $ curl --cacert certs/ca.cert https://localhost:4443/example/v1/contacts/boynton -X DELETE
    {
      "code": 403,
      "message": "Forbidden"
    }

If you look at the server's output, you can see the problem:

    2016/05/10 11:58:45 *** Authentication failed against all authenticator(s)

To authenticate and authorize, we'll use a TLS client cert. curl on the Mac unfortunately can't use PEM files for the
client cert, so we have to create a PKCS#12 file instead. the Makefile rule for test-curl does that:

    $ make test-curl
    openssl pkcs12 -password pass:example -export -in ./certs/client.cert -inkey ./keys/client.key -out ./keys/client.p12
    curl --cacert certs/ca.cert -E ./keys/client.p12:example https://localhost:4443/example/v1/contacts/boynton  -X DELETE
    $ curl --cacert certs/ca.cert https://localhost:4443/example/v1/contacts/boynton
    {
      "code": 404,
      "message": "Not Found"
    }

The delete succeeded. In the server output, you now see:

    [Authenticated 'client' from TLS client cert]
    [Authorize 'client' to DELETE on contacts]

The 'client' identifier is the CN of the client cert we used.

