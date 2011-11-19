namespace OAuth

module API = begin
    open OAuth.Utilities
    open OAuth.Types

    /// <summary>Returns the request token.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <returns>The request token.</returns>
    val getRequestToken : string -> HttpMethod -> ConsumerInfo -> string

    /// <summary>Returns the request token by GET method.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <returns>The request token.</returns>
    val getRequestTokenByGet : string -> ConsumerInfo -> string

    /// <summary>Returns the request token by POST method.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <returns>The request token.</returns>
    val getRequestTokenByPost : string -> ConsumerInfo -> string

    /// <summary>Returns the access token.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="requestInfo">The RequestInfo record.</param>
    /// <param name="pinCode">The pin code.</param>
    /// <returns>The access token.</returns>
    val getAccessToken : string -> HttpMethod -> ConsumerInfo -> RequestInfo -> string -> string

    /// <summary>Returns the access token by GET method.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="requestInfo">The RequestInfo record.</param>
    /// <param name="pinCode">The pin code.</param>
    /// <returns>The access token.</returns>
    val getAccessTokenByGet : string -> ConsumerInfo -> RequestInfo -> string -> string

    /// <summary>Returns the access token by POST method.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="requestInfo">The RequestInfo record.</param>
    /// <param name="pinCode">The pin code.</param>
    /// <returns>The access token.</returns>
    val getAccessTokenByPost : string -> ConsumerInfo -> RequestInfo -> string -> string

    /// <summary>Do something to the Web API and returns the result of it.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="accessInfo">The RequestInfo record.</param>
    /// <returns>The access token.</returns>
    val useWebService : string -> HttpMethod -> ConsumerInfo -> AccessInfo -> string

    val useWebServiceByGet : string -> ConsumerInfo -> AccessInfo -> string

    val useWebServiceByPost : string -> ConsumerInfo -> AccessInfo -> string

    val useWebServiceWithData : string -> HttpMethod -> ConsumerInfo -> AccessInfo -> string -> string
end