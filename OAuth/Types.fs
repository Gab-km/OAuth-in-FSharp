namespace OAuth.Types

type ParameterKeyValue = KeyValue of string * string

type HashAlgorithm = HMACSHA1 | PLAINTEXT | RSASHA1

type HttpMethod = GET | POST

type ConsumerInfo = { consumerKey : string; consumerSecret : string }
type RequestInfo = { requestToken : string; requestSecret : string }
type AccessInfo = { accessToken : string; accessSecret : string }

type UseFor = ForRequestToken of ConsumerInfo
            | ForAccessToken of ConsumerInfo * RequestInfo * string
            | ForWebService of ConsumerInfo * AccessInfo * (string * string) option

//type HttpRequirement = { encoding : System.Text.Encoding; targetUrl : string; httpMethod : HttpMethod }
type HttpRequirement = Requirement of System.Text.Encoding * string * HttpMethod