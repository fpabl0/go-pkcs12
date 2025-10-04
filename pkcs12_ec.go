package pkcs12

import (
	"crypto/x509"
	"errors"
	"strings"
)

func bagAttrsToMap(bag *safeBag) (map[string]string, error) {
	d := make(map[string]string, len(bag.Attributes))
	for _, attribute := range bag.Attributes {
		k, v, err := convertAttribute(&attribute)
		if err != nil {
			return nil, err
		}
		d[k] = v
	}
	return d, nil
}

// DecodeChainEC extracts a certificate, a CA certificate chain, and private key
// from pfxData, which must be a DER-encoded PKCS#12 file. This function assumes that there is at least one certificate
// and only one private key (EC Signing Key) in the pfxData.
func DecodeChainEC(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, nil, nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword, 1, 2)
	if err != nil {
		return nil, nil, nil, err
	}

	keyBags := make([]safeBag, 0, len(bags)/2)
	certBags := make([]safeBag, 0, len(bags)/2)
	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			certBags = append(certBags, bag)
		case bag.Id.Equal(oidKeyBag):
			fallthrough
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			keyBags = append(keyBags, bag)
		}
	}

	if len(certBags) == 0 {
		return nil, nil, nil, errors.New("pkcs12: certificate missing")
	}
	if len(keyBags) == 0 {
		return nil, nil, nil, errors.New("pkcs12: private key missing")
	}

	selKeyBag := &keyBags[0]
	attrMap, _ := bagAttrsToMap(selKeyBag)
	selKeyLocalID := attrMap["localKeyId"]
	if len(keyBags) > 0 {
		for _, kb := range keyBags {
			attrMap, err := bagAttrsToMap(&kb)
			if err != nil {
				continue
			}
			if strings.Contains(attrMap["friendlyName"], "EC Signing Key") {
				selKeyBag = &kb
				selKeyLocalID = attrMap["localKeyId"]
				break
			}
		}
	}

	neededCertBags := make([]safeBag, 0, len(certBags))
	for _, cb := range certBags {
		attrMap, err := bagAttrsToMap(&cb)
		if err != nil {
			continue
		}
		if certLocalKeyID, ok := attrMap["localKeyId"]; ok && certLocalKeyID != selKeyLocalID {
			continue
		}
		neededCertBags = append(neededCertBags, cb)
	}

	// -- signing certs and cas
	for _, bag := range neededCertBags {
		certsData, err := decodeCertBag(bag.Value.Bytes)
		if err != nil {
			return nil, nil, nil, err
		}
		certs, err := x509.ParseCertificates(certsData)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(certs) != 1 {
			err = errors.New("pkcs12: expected exactly one certificate in the certBag")
			return nil, nil, nil, err
		}
		if certificate == nil {
			certificate = certs[0]
		} else {
			caCerts = append(caCerts, certs[0])
		}
	}

	// -- key
	switch {
	case selKeyBag.Id.Equal(oidKeyBag):
		if privateKey, err = x509.ParsePKCS8PrivateKey(selKeyBag.Value.Bytes); err != nil {
			return nil, nil, nil, err
		}
	case selKeyBag.Id.Equal(oidPKCS8ShroundedKeyBag):
		if privateKey, err = decodePkcs8ShroudedKeyBag(selKeyBag.Value.Bytes, encodedPassword); err != nil {
			return nil, nil, nil, err
		}
	}

	if certificate == nil {
		return nil, nil, nil, errors.New("pkcs12: certificate missing")
	}
	if privateKey == nil {
		return nil, nil, nil, errors.New("pkcs12: private key missing")
	}

	return
}
