namespace OAuth

module API = begin
    open OAuth.Utilities
    open OAuth.Types

    val getRequestToken : string -> HttpMethod -> ConsumerInfo -> string

    val getRequestTokenByGet : string -> ConsumerInfo -> string

    val getRequestTokenByPost : string -> ConsumerInfo -> string

    val getAccessToken : string -> HttpMethod -> ConsumerInfo -> RequestInfo -> string -> string

    val getAccessTokenByGet : string -> ConsumerInfo -> RequestInfo -> string -> string

    val getAccessTokenByPost : string -> ConsumerInfo -> RequestInfo -> string -> string

    val useWebService : string -> HttpMethod -> ConsumerInfo -> AccessInfo -> string

    val useWebServiceByGet : string -> ConsumerInfo -> AccessInfo -> string

    val useWebServiceByPost : string -> ConsumerInfo -> AccessInfo -> string
end