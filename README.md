# Erlang SignedPublicKeyAndChallenge decoder

Espkac is a pure-Erlang decoder of SPKAC binary data.

## Use cases
- HTML5 `<keygen>` element server-side handler
- common conversion of SPKAC to PEM

## Usage

### HTML5 KeyGen
```Erlang
QueryProps = mochiweb_util:parse_qs (RequestQueryString),
KeyGenData = proplists:get_value (my_keygen_field, QueryProps),
PubKeyPEM = espkac:spkac2pem (base64:decode (KeyGenData))
```

# References
- https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen
- http://en.wikipedia.org/wiki/SPKAC
- http://en.wikipedia.org/wiki/SPKI
