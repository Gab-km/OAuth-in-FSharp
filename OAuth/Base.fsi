namespace OAuth

module Base = begin
    open System.Text
    open OAuth.Utilities
    open OAuth.Types
    
    /// <summary>Returns a ParamerterKeyValue list from a string tuple list.</summary>
    /// <param name="tupleList">The list of 2 strings tuple.</param>
    /// <returns>The ParameterKeyValue list.</returns>
    val keyValueMany : (string * string) list -> ParameterKeyValue list

    /// <summary>Returns a string as a HTTP header parameter.</summary>
    /// <param name="keyValues">The ParameterKeyValue list.</param>
    /// <returns>The HTTP header parameter.</returns>
    val headerParameter : ParameterKeyValue list -> string

    /// <summary>Returns a string combined with an equal sign.</summary>
    /// <param name="keyValue">The ParameterKeyValue.</param>
    /// <returns>The key and value strings combined with an equal sign.<returns>
    val parameterize : Encoding -> ParameterKeyValue -> string

    /// <summary>Returns a parameterized string combined with an ampersand sign.</summary>
    /// <param name="keyValues">The ParameterKeyValue list.</param>
    /// <returns>The parameterized strings combined with an ampersand sign.
    /// Or the parameterized string with an ampersand with its tail.</returns>
    val toParameter : Encoding -> ParameterKeyValue list -> string

    /// <summary>Returns a ParameterKeyValue list from a parameterized string.</summary>
    /// <param name="parameterString">The parameterized string combined with an ampersand sign.</param>
    /// <returns>The ParameterKeyValue list.</returns>
    val fromParameter : string -> ParameterKeyValue list

    /// <summary>Try to return a value from a ParameterKeyValue list.<br />
    /// Returns a Some value when the key matches a given key.<br />
    /// Returns None when the key doesn't match.</summary>
    /// <param name="key">The input key.</param>
    /// <param name="keyValues">The ParameterKeyValue list.</param>
    /// <returns>The value mapped to the given key.</returns>
    val tryGetValue : string -> ParameterKeyValue list -> string option

    /// <summary>Returns the ticks strings of DateTime.Now .</summary>
    /// <returns>The strings of the ticks represents the date and the time of DateTime.Now .</returns>
    val inline generateNonce : unit -> string

    /// <summary>Returns the time stamp that is expressed in the number of seconds
    /// since January 1, 1970 00:00:00 GMT.</summary>
    /// <returns>The time stamp since Jan 1, 1970.</returns>
    val generateTimeStamp : unit -> string

    /// <summary>Returns the signature with the given method.</summary>
    /// <param name="algorithmType">The hash algorithm.</param>
    /// <param name="secretKeys">The string list of the secret keys.</param>
    /// <param name="baseString">The base string.</param>
    /// <returns>The signature which is encoded with Base64 digits and sanitized.</returns>
    val generateSignature : Encoding -> HashAlgorithm -> string list -> string -> string

    /// <summary>Returns the signature with HMAC-SHA1 algorithm.</summary>
    /// <param name="secretKeys">The string list of the secret keys.</param>
    /// <param name="baseString">The base string.</param>
    /// <returns>The signature which is encoded with Base64 digits and sanitized.</returns>
    val inline generateSignatureWithHMACSHA1 : Encoding -> string list -> string -> string

    /// <summary>Returns the signature without any criptographies.</summary>
    /// <param name="secretKeys">The string list of the secret keys.</param>
    /// <param name="baseString">The base string.</param>
    /// <returns>The signature which is encoded with Base64 digits and sanitized.</returns>
    val inline generateSignatureWithPLAINTEXT : Encoding -> string list -> string -> string

    /// <summary>Returns the signature with RSA-SHA1 algorithm.</summary>
    /// <param name="secretKeys">The string list of the secret keys.</param>
    /// <param name="baseString">The base string.</param>
    /// <returns>The signature which is encoded with Base64 digits and sanitized.</returns>
    /// <remark>This function is not implemented and throws the NotImplementedException
    /// when you use this.</remark>
    val inline generateSignatureWithRSASHA1 : Encoding -> string list -> string -> string

    /// <summary>Returns the string that represents the HTTP method.</summary>
    /// <param name="httpMethod">The Http Method.</param>
    /// <returns>The string of the HTTP method.</returns>
    val getHttpMethodString : HttpMethod -> string

    /// <summary>Returns the base string.</summary>
    /// <param name="meth">The string representation of the HTTP method.</param>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="keyValues">The ParameterKeyValue list.</param>
    /// <returns>The base string.</returns>
    val assembleBaseString : Encoding -> string -> string -> ParameterKeyValue list -> string

    /// <summary>Returns the list of 2 strings tuple.</summary>
    /// <param name="useFor">The parameter of the OAuth API.</param>
    /// <returns>The list of 2 strings tuple.</returns>
    val makeKeyValueTuplesForGenerateHeader : UseFor -> (string * string) list

    /// <summary>Returns the Authorization parameter in the HTTP header.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The string that represents the HTTP method.</param>
    /// <param name="useFor">The parameter of the OAuth API.</param>
    /// <returns>The Authorization parameter in the HTTP header.</returns>
    val generateAuthorizationHeader : Encoding -> string -> string -> UseFor -> string

    /// <summary>Returns the Authorization parameter in the HTTP header for the request token.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The string that represents the HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <returns>The Authorization parameter in the HTTP header for the request token.</returns>
    val generateAuthorizationHeaderForRequestToken : Encoding -> string -> string -> ConsumerInfo -> string

    /// <summary>Returns the Authorization parameter in the HTTP header for the access token.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The string that represents the HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="requestInfo">The RequestInfo record.</param>
    /// <param name="pinCode">The pin code.</param>
    /// <returns>The Authorization parameter in the HTTP header for the access token.</returns>
    val generateAuthorizationHeaderForAccessToken : Encoding -> string -> string -> ConsumerInfo -> RequestInfo -> string -> string

    /// <summary>Returns the Authorization parameter in the HTTP header for using Web APIs.</summary>
    /// <param name="targetUrl">The URL string.</param>
    /// <param name="httpMethod">The string that represents the HTTP method.</param>
    /// <param name="consumerInfo">The ConsumerInfo record.</param>
    /// <param name="accessInfo">The AccessInfo record.</param>
    /// <returns>The Authorization parameter in the HTTP header for using Web APIs.</returns>
    val generateAuthorizationHeaderForWebService : Encoding -> string -> string -> ConsumerInfo -> AccessInfo -> string

    val generateAuthorizationHeaderForWebServiceWithData : Encoding -> string -> string -> ConsumerInfo -> AccessInfo -> string -> string
end