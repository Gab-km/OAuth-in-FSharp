namespace OAuth.Core

module Authentication = begin
    open OAuth.Utilities
    open OAuth.Types
    open OAuth.Core.Base

    /// <summary>Returns the ticks string of DateTime.Now .</summary>
    /// <returns>The strings of the ticks represents the date and the time of DateTime.Now .</returns>
    [<CompiledName("GenerateNonce")>]
    val inline generateNonce : unit -> string

    /// <summary>Returns the time stamp that is expressed in the number of seconds
    /// since January 1, 1970 00:00:00 GMT.</summary>
    /// <returns>The time stamp since Jan 1, 1970.</returns>
    [<CompiledName("GenerateTimeStamp")>]
    val generateTimeStamp : unit -> string

    /// <summary>Returns the signature with the given method.</summary>
    /// <param name="encoder">The encoding function.</param>
    /// <param name="algorithmType">The hash algorithm.</param>
    /// <param name="secretKeys">The string list of the secret keys.</param>
    /// <param name="baseString">The base string.</param>
    /// <returns>The signature which is encoded with Base64 digits and sanitized.</returns>
    [<CompiledName("GenerateSignature")>]
    val generateSignature : (string -> string) -> HashAlgorithm -> string list -> string -> string

    /// <summary>Returns the signature with HMAC-SHA1 algorithm.</summary>
    /// <param name="encoder">The encoding function.</param>
    /// <param name="secretKeys">The string list of the secret keys.</param>
    /// <param name="baseString">The base string.</param>
    /// <returns>The signature which is encoded with Base64 digits and sanitized.</returns>
    [<CompiledName("GenerateSignatureWithHMACSHA1")>]
    val inline generateSignatureWithHMACSHA1 : (string -> string) -> string list -> string -> string

    /// <summary>Returns the signature without any criptographies.</summary>
    /// <param name="encoder">The encoding function.</param>
    /// <param name="secretKeys">The string list of the secret keys.</param>
    /// <param name="baseString">The base string.</param>
    /// <returns>The signature which is encoded with Base64 digits and sanitized.</returns>
    [<CompiledName("GenerateSignatureWithPLAINTEXT")>]
    val inline generateSignatureWithPLAINTEXT : (string -> string) -> string list -> string -> string

    /// <summary>Returns the signature with RSA-SHA1 algorithm.</summary>
    /// <param name="encoder">The encoding function.</param>
    /// <param name="secretKeys">The string list of the secret keys.</param>
    /// <param name="baseString">The base string.</param>
    /// <returns>The signature which is encoded with Base64 digits and sanitized.</returns>
    /// <remark>This function is not implemented and throws the NotImplementedException
    /// when you use this.</remark>
    [<CompiledName("GenerateSignatureWithRSASHA1")>]
    val inline generateSignatureWithRSASHA1 : (string -> string) -> string list -> string -> string

    /// <summary>Returns the base string.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="keyValues">The ParameterKeyValue list.</param>
    /// <returns>The base string.</returns>
    [<CompiledName("AssembleBaseString")>]
    val assembleBaseString : HttpRequirement -> ParameterKeyValue list -> string

    /// <summary>Returns the list of 2 strings tuple.</summary>
    /// <param name="useFor">The parameter of the OAuth API.</param>
    /// <returns>The list of 2 strings tuple.</returns>
    [<CompiledName("MakeStringPairForGenerateHeader")>]
    val makeStringPairForGenerateHeader : UseFor -> (string * string) list

    /// <summary>Returns the Authorization parameter in the HTTP header.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="useFor">The parameter of the OAuth API.</param>
    /// <returns>The Authorization parameter in the HTTP header.</returns>
    [<CompiledName("GenerateAuthorizationHeader")>]
    val generateAuthorizationHeader : HttpRequirement -> UseFor -> string

    /// <summary>Returns the Authorization parameter in the HTTP header for the request token.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <returns>The Authorization parameter in the HTTP header for the request token.</returns>
    [<CompiledName("GenerateAuthorizationHeaderForRequestToken")>]
    val generateAuthorizationHeaderForRequestToken : HttpRequirement -> ConsumerInfo -> string

    /// <summary>Returns the Authorization parameter in the HTTP header for the access token.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="requestInfo">The RequestInfo record.</param>
    /// <param name="pinCode">The pin code.</param>
    /// <returns>The Authorization parameter in the HTTP header for the access token.</returns>
    [<CompiledName("GenerateAuthorizationHeaderForAccessToken")>]
    val generateAuthorizationHeaderForAccessToken : HttpRequirement -> ConsumerInfo -> RequestInfo -> string -> string

    /// <summary>Returns the Authorization parameter in the HTTP header for using Web APIs.</summary>
    /// <param name="requirement">The HTTP requirement parameter.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="accessInfo">The AccessInfo record.</param>
    /// <param name="parameter">The Web API parameter.</param>
    /// <returns>The Authorization parameter in the HTTP header for using Web APIs.</returns>
    [<CompiledName("GenerateAuthorizationHeaderForWebService")>]
    val generateAuthorizationHeaderForWebService : HttpRequirement -> ConsumerInfo -> AccessInfo -> ParameterKeyValue list -> string
end