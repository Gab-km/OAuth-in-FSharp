namespace OAuth

module API = begin
    open System.Text
    open OAuth.Utilities
    open OAuth.Types

    /// <summary>Returns the request token.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="header">The Authentication parameter in the HTTP header.</param>
    /// <param name="parameter">The Web API parameter.</param>
    /// <returns>The request token.</returns>
    /// <remark>The <paramref name="data" /> parameter works only the ASCII characters.</remark>
    [<CompiledName("AsyncAPIBase")>]
    val asyncAPIBase : HttpRequirement -> string -> ParameterKeyValue list -> string

    /// <summary>Returns the request token.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="parameter">The Web API parameter.</param>
    /// <returns>The request token.</returns>
    /// <remark>The <paramref name="data" /> parameter works only the ASCII characters.</remark>
    [<CompiledName("GetRequestToken")>]
    val getRequestToken : HttpRequirement -> ConsumerInfo -> ParameterKeyValue list -> string

    /// <summary>Returns the access token.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="requestInfo">The RequestInfo record.</param>
    /// <param name="pinCode">The pin code.</param>
    /// <param name="parameter">The Web API parameter.</param>
    /// <returns>The access token.</returns>
    /// <remark>The <paramref name="data" /> parameter works only the ASCII characters.</remark>
    [<CompiledName("GetAccessToken")>]
    val getAccessToken : HttpRequirement -> ConsumerInfo -> RequestInfo -> string -> ParameterKeyValue list -> string

    /// <summary>Do something to the Web API and returns the result of it.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="accessInfo">The RequestInfo record.</param>
    /// <param name="parameter">The Web API parameter.</param>
    /// <returns>The access token.</returns>
    /// <remark>The <paramref name="data" /> parameter works only the ASCII characters.</remark>
    [<CompiledName("UseWebService")>]
    val useWebService : HttpRequirement -> ConsumerInfo -> AccessInfo -> ParameterKeyValue list -> string
end