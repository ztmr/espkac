-module (espkac).
-export ([spki2pem/1, spkac2pem/1, extract_info/1]).

-include ("SPKAC.hrl").
-include ("AuthenticationFramework.hrl").
-include ("PKCS-1.hrl").

-define (SPKAC, 'SignedPublicKeyAndChallenge').
-define (PKAC, 'PublicKeyAndChallenge').
-define (SPKI, 'SubjectPublicKeyInfo').
-define (AID, 'AlgorithmIdentifier').

%% @doc Convert a SPKAC binary to human-readable proplist.
%% A valid input is SPKAC binary or SPKAC record.
%%
%% Algorithm OIDs are converted to their names,
%% Key and Signature is converted to hexadecimal string,
%% Challenge is left as a string.
extract_info (Data) when is_binary (Data) ->
    {ok, #?SPKAC {} = SPKAC} = 'SPKAC':decode (?SPKAC, Data),
    extract_info (SPKAC);
extract_info (#?SPKAC {
                  publicKeyAndChallenge = #?PKAC {
                      spki = #?SPKI {
                          algorithm = #?AID {
                              algorithm = PubKeyAlgo
                          },
                          subjectPublicKey = PubKey
                      },
                      challenge = Challenge
                  },
                  signatureAlgorithm = #?AID { algorithm = SignatureAlgo },
                  signature = Signature }) ->
    PubKeyHex = bits2hex (PubKey),
    PubKeyAlgoName = algo (PubKeyAlgo),
    SignatureHex = bits2hex (Signature),
    SignatureAlgoName = algo (SignatureAlgo),
    [{pubkey_algorithm, PubKeyAlgoName}, {pubkey, PubKeyHex},
     {challenge, Challenge}, {signature_algorithm, SignatureAlgoName},
     {signature, SignatureHex}].

%% @doc Convert SPKAC to PEM.
%% A valid input is SPKI/SPKAC record or SPKAC binary data.
spkac2pem (#?SPKI {} = SPKI) -> spki2pem (SPKI);
spkac2pem (#?SPKAC { publicKeyAndChallenge = #?PKAC { spki = SPKI } }) ->
    spki2pem (SPKI);
spkac2pem (Data) when is_binary (Data) ->
    {ok, #?SPKAC {} = SPKAC} = 'SPKAC':decode (?SPKAC, Data),
    spkac2pem (SPKAC).

%% @doc Convert SPKI to PEM.
%% A valid input is SPKI record.
spki2pem (#?SPKI {} = SPKI) ->
    PEMEntry = public_key:pem_entry_encode ('SubjectPublicKeyInfo', SPKI),
    public_key:pem_encode ([PEMEntry]).

algo (?'rsaEncryption') -> "rsaEncryption";
algo (?'md5WithRSAEncryption') -> "md5WithRSAEncryption";
algo (?'sha1WithRSAEncryption') -> "sha1WithRSAEncryption";
algo (?'sha256WithRSAEncryption') -> "sha256WithRSAEncryption";
algo (?'sha384WithRSAEncryption') -> "sha384WithRSAEncryption";
algo (?'sha512WithRSAEncryption') -> "sha512WithRSAEncryption";
algo (?'sha224WithRSAEncryption') -> "sha224WithRSAEncryption";
algo (Algo) -> io_lib:format ("~p", [Algo]).

bits2hex (Bits) ->
    %integer_to_list (idealib_conv:bits2int (Bits), 16).
    integer_to_list (list_to_integer ([ $0+Xi || Xi <- Bits ], 2), 16).

%% EUnit Tests
-ifdef (TEST).
-include_lib ("eunit/include/eunit.hrl").

decode_test () ->
    SPKAC = lists:concat ([
      "MIHFMHEwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAnX0TILJrOMUue+PtwBRE6XfV\n",
      "WtKQbsshxk5ZhcUwcwyvcnIq9b82QhJdoACdD34rqfCAIND46fXKQUnb0mvKzQID\n",
      "AQABFhFNb3ppbGxhSXNNeUZyaWVuZDANBgkqhkiG9w0BAQQFAANBAAKv2Eex2n/S\n",
      "r/7iJNroWlSzSMtTiQTEB+ADWHGj9u1xrUrOilq/o2cuQxIfZcNZkYAkWP4DubqW\n",
      "i0//rgBvmco=" ]),
    PEM = list_to_binary ([
      <<"-----BEGIN PUBLIC KEY-----\n">>,
      <<"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ19EyCyazjFLnvj7cAUROl31VrSkG7L\n">>,
      <<"IcZOWYXFMHMMr3JyKvW/NkISXaAAnQ9+K6nwgCDQ+On1ykFJ29Jrys0CAwEAAQ==\n">>,
      <<"-----END PUBLIC KEY-----\n\n">> ]),
    ?assertEqual (PEM, spkac2pem (base64:decode (SPKAC))).

-endif.

%% vim: fdm=syntax:fdn=3:tw=74:ts=2:syn=erlang
