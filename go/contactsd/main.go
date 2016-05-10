package main

import (
	"contacts"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/ardielle/ardielle-go/rdl"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func now() rdl.Timestamp {
	return rdl.TimestampNow()
}

func main() {
	endpoint := "localhost:4443"

	url := "https://" + endpoint + "/example/v1"

	impl := new(ContactsImpl)
	impl.baseUrl = url
	impl.contacts = make(map[contacts.Identifier]ContactEntry)

	if true {
		//test user
		user := contacts.Identifier(os.Getenv("USER"))
		attrs := []*contacts.Attribute{&contacts.Attribute{Label: "email", Value: string(user) + "@yahoo-inc.com"}}
		now := now()
		impl.contacts[user] = ContactEntry{contacts.Contact{Id: user, Modified: now, Attributes: attrs}, nil}
	}

	handler := contacts.Init(impl, url, impl)

	if strings.HasPrefix(url, "https") {
		config, err := TLSConfiguration()
		if err != nil {
			log.Fatal("Cannot set up TLS: " + err.Error())
		}
		listener, err := tls.Listen("tcp", endpoint, config)
		if err != nil {
			panic(err)
		}
		log.Fatal(http.Serve(listener, handler))
	} else {
		log.Fatal(http.ListenAndServe(endpoint, handler))
	}
}

// ContactEntry - each entry in the map of the store contains an entry.
type ContactEntry struct {
	contact   contacts.Contact
	listeners []chan string
}

//
// ContactsImpl is the implementation of the CapsHandler interface
//
type ContactsImpl struct {
	contacts map[contacts.Identifier]ContactEntry
	mutex    sync.RWMutex
	baseUrl  string
}

func (impl *ContactsImpl) validateContact(contact *contacts.Contact) error {
	if contact == nil {
		return &rdl.ResourceError{Code: 400, Message: "Bad Request"}
	}
	return contact.Validate() //should be a more comprehensive version, checking regexes, etc
}

// PostContact implementation
func (impl *ContactsImpl) PostContact(context *rdl.ResourceContext, contact *contacts.Contact) (*contacts.Contact, string, error) {
	err := impl.validateContact(contact)
	if err != nil {
		return nil, "", err
	}
	contactID := contact.Id
	contact.Modified = now()
	newEntry := ContactEntry{*contact, nil}
	impl.mutex.Lock()
	_, exists := impl.contacts[contactID]
	if !exists {
		impl.contacts[contactID] = newEntry
	}
	impl.mutex.Unlock()
	if exists {
		return nil, "", &rdl.ResourceError{Code: 409, Message: "Contact already exists: " + string(contactID)}
	}
	loc := impl.baseUrl + "/contacts/" + string(contactID)
	return contact, loc, nil
}

// GetContact implementation
func (impl *ContactsImpl) GetContact(context *rdl.ResourceContext, contactID contacts.Identifier, timeout int32, revisedSince string) (*contacts.Contact, string, error) {
	impl.mutex.RLock()
	entry, ok := impl.contacts[contactID] //note entry is a copied value, cannot be modified accidently
	impl.mutex.RUnlock()
	if ok {
		smodified := entry.contact.Modified.String()
		if smodified == revisedSince {
			if timeout <= 0 {
				return nil, "", rdl.ResourceError{Code: 304, Message: "Not Modified"}
			}
			return impl.waitForChange(contactID, revisedSince, timeout)
		}
		return &entry.contact, smodified, nil
	}
	return nil, "", &rdl.ResourceError{Code: 404, Message: "Not Found"}
}

func (impl *ContactsImpl) waitForChange(contactID contacts.Identifier, revisedSince string, timeout int32) (*contacts.Contact, string, error) {
	impl.mutex.Lock()
	if entry, ok := impl.contacts[contactID]; ok {
		smodified := entry.contact.Modified.String()
		if smodified == revisedSince {
			timeouts := make(chan bool)
			changes := make(chan string)
			entry.listeners = append(entry.listeners, changes)
			impl.contacts[contactID] = entry

			impl.mutex.Unlock()
			go func() {
				time.Sleep(time.Duration(timeout) * time.Second)
				timeouts <- true
			}()
			select {
			case change := <-changes: //the emitter should have deleted the change listener, also
				impl.mutex.RLock()
				entry, ok := impl.contacts[contactID] //this is a copy
				impl.mutex.RUnlock()
				if ok {
					if change != revisedSince {
						return &entry.contact, entry.contact.Modified.String(), nil
					}
					return nil, "", &rdl.ResourceError{Code: 304, Message: "Not Modified"}
				}
				return nil, "", &rdl.ResourceError{Code: 404, Message: "Not Found"}
			case _ = <-timeouts:
				return nil, "", &rdl.ResourceError{Code: 304, Message: "Not Modified"}
			}
		}
		impl.mutex.Unlock()
		return &entry.contact, smodified, nil
	}
	impl.mutex.Unlock()
	return nil, "", &rdl.ResourceError{Code: 404, Message: "Not Found"}

}

// PutContact implementation
func (impl *ContactsImpl) PutContact(context *rdl.ResourceContext, contactID contacts.Identifier, contact *contacts.Contact) (*contacts.Contact, error) {
	fmt.Println("put contact", contactID, "->", contact)
	err := impl.validateContact(contact)
	if err != nil {
		return nil, err
	}
	if contactID != contact.Id {
		return nil, &rdl.ResourceError{Code: 400, Message: "Bad Request"}
	}
	contact.Modified = now()
	impl.mutex.Lock()
	var listeners []chan string
	newEntry := ContactEntry{*contact, nil}
	if entry, ok := impl.contacts[contactID]; ok {
		listeners = entry.listeners
	}
	impl.contacts[contactID] = newEntry
	impl.mutex.Unlock()
	etag := contact.Modified.String() //we could type the header all the way out.
	if len(listeners) > 0 {
		for _, c := range listeners {
			fmt.Println("notify", c)
			c <- etag
		}
	}
	return contact, nil
}

// DeleteContact implementation
func (impl *ContactsImpl) DeleteContact(context *rdl.ResourceContext, contactID contacts.Identifier) error {
	impl.mutex.Lock()
	var listeners []chan string
	entry, ok := impl.contacts[contactID]
	if ok {
		listeners = entry.listeners
		delete(impl.contacts, contactID)
	}
	impl.mutex.Unlock()
	if len(listeners) > 0 {
		for _, c := range listeners {
			c <- "_deleted"
		}
	}
	if !ok {
		return &rdl.ResourceError{Code: 404, Message: "Not Found"}
	}
	return nil
}

// GetContactList implementation
func (impl *ContactsImpl) GetContactList(context *rdl.ResourceContext, start int32, count *int32, label string, value string) (*contacts.ContactList, error) {
	impl.mutex.RLock()
	var ids []contacts.Identifier
	for id, e := range impl.contacts {
		match := true
		if e.contact.Attributes != nil {
			if label != "" && value != "" {
				match = false
				for _, kv := range e.contact.Attributes {
					if label == kv.Label {
						if value == kv.Value {
							match = true
							break
						}
					}
				}
			} else if label != "" {
				match = false
				for _, kv := range e.contact.Attributes {
					if label == kv.Label {
						match = true
						break
					}
				}
			} else if value != "" {
				match = false
				for _, kv := range e.contact.Attributes {
					if value == kv.Value {
						match = true
						break
					}
				}
			}
		}
		if match {
			ids = append(ids, id)
		}
	}
	ids = ids[start:]
	result := new(contacts.ContactList)
	if count != nil {
		if *count < int32(len(ids)) {
			n := start + *count
			result.Next = &n
			ids = ids[0:*count]
		}
	}
	tmp := make([]*contacts.Contact, 0, len(ids))
	for _, k := range ids {
		e := impl.contacts[k]
		tmp = append(tmp, &e.contact)
	}
	result.Contacts = tmp
	impl.mutex.RUnlock()
	return result, nil
}

//
// the following is to support TLS-based authentication, and self-authorization that just logs what if *could* enforce.
//

func (impl *ContactsImpl) Authorize(action string, resource string, principal rdl.Principal) (bool, error) {
	fmt.Printf("[Authorize '%v' to %v on %v]\n", principal, action, resource)
	return true, nil
}

func (impl *ContactsImpl) Authenticate(context *rdl.ResourceContext) bool {
	certs := context.Request.TLS.PeerCertificates
	for _, cert := range certs {
		fmt.Printf("[Authenticated '%s' from TLS client cert]\n", cert.Subject.CommonName)
		context.Principal = &TLSPrincipal{cert}
		return true
	}
	return false
}

type TLSPrincipal struct {
	Cert *x509.Certificate
}

func (p *TLSPrincipal) String() string {
	return p.GetYRN()
}

func (p *TLSPrincipal) GetDomain() string {
	cn := p.Cert.Subject.CommonName
	i := strings.LastIndex(cn, ".")
	return cn[0:i]
}

func (p *TLSPrincipal) GetName() string {
	cn := p.Cert.Subject.CommonName
	i := strings.LastIndex(cn, ".")
	return cn[i+1:]
}

func (p *TLSPrincipal) GetYRN() string {
	return p.Cert.Subject.CommonName
}

func (p TLSPrincipal) GetCredentials() string {
	return ""
}

func (p TLSPrincipal) GetHTTPHeaderName() string {
	return ""
}

func TLSConfiguration() (*tls.Config, error) {
	capem, err := ioutil.ReadFile("certs/ca.cert")
	if err != nil {
		return nil, err
	}
	config := &tls.Config{}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(capem) {
		return nil, fmt.Errorf("Failed to append certs to pool")
	}
	config.RootCAs = certPool

	keypem, err := ioutil.ReadFile("keys/contacts.key")
	if err != nil {
		return nil, err
	}
	certpem, err := ioutil.ReadFile("certs/contacts.cert")
	if err != nil {
		return nil, err
	}
	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert

		config.ClientCAs = certPool

		//config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientAuth = tls.VerifyClientCertIfGiven
	}

	//Use only modern ciphers
	config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	//Use only TLS v1.2
	config.MinVersion = tls.VersionTLS12

	//Don't allow session resumption
	config.SessionTicketsDisabled = true
	return config, nil

}
