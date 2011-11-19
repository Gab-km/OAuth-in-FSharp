namespace OAuth

module API = begin
    open System.Text
    open OAuth.Utilities
    open OAuth.Types

    /// <summary>Returns the request token.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="data">The input option that represents the string data.</param>
    /// <returns>The request token.</returns>
    /// <remark>The <paramref name="data" /> parameter works only the ASCII characters.</remark>
    val getRequestToken : HttpRequirement -> ConsumerInfo -> string option -> string

    /// <summary>Returns the access token.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="requestInfo">The RequestInfo record.</param>
    /// <param name="pinCode">The pin code.</param>
    /// <param name="data">The input option that represents the string data.</param>
    /// <returns>The access token.</returns>
    /// <remark>The <paramref name="data" /> parameter works only the ASCII characters.</remark>
    val getAccessToken : HttpRequirement -> ConsumerInfo -> RequestInfo -> string -> string option -> string

    /// <summary>Do something to the Web API and returns the result of it.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="accessInfo">The RequestInfo record.</param>
    /// <param name="data">The input option that represents the string data.</param>
    /// <returns>The access token.</returns>
    /// <remark>The <paramref name="data" /> parameter works only the ASCII characters.</remark>
    val useWebService : HttpRequirement -> ConsumerInfo -> AccessInfo -> string option -> string
end