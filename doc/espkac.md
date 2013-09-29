

# Module espkac #
* [Function Index](#index)
* [Function Details](#functions)


<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#extract_info-1">extract_info/1</a></td><td>Convert a SPKAC binary to human-readable proplist.</td></tr><tr><td valign="top"><a href="#spkac2pem-1">spkac2pem/1</a></td><td>Convert SPKAC to PEM.</td></tr><tr><td valign="top"><a href="#spki2pem-1">spki2pem/1</a></td><td>Convert SPKI to PEM.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="extract_info-1"></a>

### extract_info/1 ###

`extract_info(Data) -> any()`


Convert a SPKAC binary to human-readable proplist.
A valid input is SPKAC binary or SPKAC record.


Algorithm OIDs are converted to their names,
Key and Signature is converted to hexadecimal string,
Challenge is left as a string.
<a name="spkac2pem-1"></a>

### spkac2pem/1 ###

`spkac2pem(?SPKI) -> any()`

Convert SPKAC to PEM.
A valid input is SPKI/SPKAC record or SPKAC binary data.
<a name="spki2pem-1"></a>

### spki2pem/1 ###

`spki2pem(?SPKI) -> any()`

Convert SPKI to PEM.
A valid input is SPKI record.
