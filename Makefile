export GOPATH=$(PWD)/go
RDL ?= $(GOPATH)/bin/rdl

all: go/bin/contactsd

go/bin/contactsd: keys go/src/contactsd go/src/contacts go/src/github.com/dimfeld/httptreemux
	go install contactsd

keys:
	rm -rf keys certs
	go run ca/gencerts.go

keys/client.p12: keys/client.key
	openssl pkcs12 -password pass:example -export -in ./certs/client.cert -inkey ./keys/client.key -out ./keys/client.p12

test-curl: keys/client.p12
	curl --cacert certs/ca.cert -E ./keys/client.p12:example https://localhost:4443/example/v1/contacts/$(USER)  -X DELETE

go/src/github.com/dimfeld/httptreemux:
	go get github.com/dimfeld/httptreemux

go/src/contacts: rdl/contacts.rdl $(RDL)
	mkdir -p go/src/contacts
	$(RDL) -ps generate -t -o go/src/contacts go-model rdl/contacts.rdl
	$(RDL) -ps generate -t -o go/src/contacts go-server rdl/contacts.rdl
	$(RDL) -ps generate -t -o go/src/contacts go-client rdl/contacts.rdl

go/src/contactsd:
	mkdir -p go/src
	(cd go/src; ln -s ../contactsd)

$(RDL):
	go get github.com/ardielle/ardielle-tools/...

bin/$(NAME): generated src/contactsd/main.go
	go install $(NAME)

src/contactsd/main.go:
	(cd src; ln -s .. contactsd)

clean::
	rm -rf go/bin go/pkg go/src keys certs go/contacts

swagger::
	echo point swagger at http://localhost:8080/contacts.json
	$(RDL) -ps generate -o localhost:8080 swagger rdl/contacts.rdl
