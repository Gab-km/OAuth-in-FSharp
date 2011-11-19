namespace OAuth.Types

/// <summary>A key-value parameter.</summary>
type ParameterKeyValue = | KeyValue of string * string

/// <summary>A hash algorithm which is HMAC-SHA1, PLAINTEXT or RSA-SHA1.</summary>
type HashAlgorithm =
    | HMACSHA1
    | PLAINTEXT
    | RSASHA1

/// <summary>An HTTP method, GET or POST.</summary>
type HttpMethod =
    | GET
    | POST

/// <summary>A consumer key and a consumer secret.
/// These key and secret are used in getting every tokens and using OAuth API.</summary>
type ConsumerInfo =
    { consumerKey : string;
    consumerSecret : string }

/// <summary>A request token and a request secret.
/// These key and secret are used in getting the access token.</summary>
type RequestInfo =
    { requestToken : string;
    requestSecret : string }

/// <summary>An access token and an access secret.
/// These key and secret are used in using OAuth API.</summary>
type AccessInfo =
    { accessToken : string;
    accessSecret : string }

/// <summary>A pack of parameter which uses in our APIs.</summary>
type UseFor =
    | ForRequestToken of ConsumerInfo
    | ForAccessToken of ConsumerInfo * RequestInfo * string
    | ForWebService of ConsumerInfo * AccessInfo * (string * string) option

/// <summary>A pack of parameter for HTTP actions.</summary>
type HttpRequirement = | Requirement of System.Text.Encoding * string * HttpMethod