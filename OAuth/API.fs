module OAuth.API

open OAuth.Base
open OAuth.ExtendedWebClient

let getRequestToken target httpMethod consumerInfo =
    async {
        let wc = new System.Net.WebClient ()
        let url = System.Uri (target)
        let meth = getHttpMethodString httpMethod
        let header = generateAuthorizationHeaderForRequestToken target meth consumerInfo
        wc.Headers.Add ("Authorization", header)
        let! result = wc.AsyncUploadString url meth ""
        return result |> fromKeyValue
    } |> Async.RunSynchronously

let getRequestTokenByGet target consumerInfo = getRequestToken target GET consumerInfo
let getRequestTokenByPost target consumerInfo = getRequestToken target POST consumerInfo

let getAccessToken target httpMethod consumerInfo requestInfo pinCode =
    async {
        let wc = new System.Net.WebClient ()
        let url = System.Uri (target)
        let meth = getHttpMethodString httpMethod
        let { consumerKey=consumerKey; consumerSecret=consumerSecret } = consumerInfo
        let { requestToken=requestToken; requestSecret=requestSecret } = requestInfo
        let header = generateAuthorizationHeaderForAccessToken target meth consumerKey requestToken pinCode [consumerSecret; requestSecret]
        wc.Headers.Add ("Authorization", header)
        let! result = wc.AsyncUploadString url meth ""
        return result |> fromKeyValue
    } |> Async.RunSynchronously

let getAccessTokenByGet target consumerInfo requestInfo pinCode = getAccessToken target GET consumerInfo requestInfo pinCode
let getAccessTokenByPost target consumerInfo requestInfo pinCode = getAccessToken target POST consumerInfo requestInfo pinCode
