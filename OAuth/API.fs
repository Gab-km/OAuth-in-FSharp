module OAuth.API

open OAuth.Types
open OAuth.Base
open OAuth.ExtendedWebClient

let getRequestToken target httpMethod consumerInfo =
    async {
        let wc = new System.Net.WebClient ()
        let url = System.Uri (target)
        let meth = getHttpMethodString httpMethod
        let! result =
            match httpMethod with
            | GET ->
                let header = generateAuthorizationHeaderForRequestToken target meth consumerInfo
                wc.Headers.Add ("Authorization", header)
                wc.AsyncDownloadString url
            | POST ->
                let header = generateAuthorizationHeaderForRequestToken target meth consumerInfo
                wc.Headers.Add ("Authorization", header)
                wc.AsyncUploadString url meth ""
        return result |> fromKeyValue
    } |> Async.RunSynchronously

let getRequestTokenByGet target consumerInfo = getRequestToken target GET consumerInfo
let getRequestTokenByPost target consumerInfo = getRequestToken target POST consumerInfo

let getAccessToken target httpMethod consumerInfo requestInfo pinCode =
    async {
        let wc = new System.Net.WebClient ()
        let url = System.Uri (target)
        let meth = getHttpMethodString httpMethod
        let! result =
            match httpMethod with
            | GET ->
                let header = generateAuthorizationHeaderForAccessToken target meth consumerInfo requestInfo pinCode
                wc.Headers.Add ("Authorization", header)
                wc.AsyncDownloadString url
            | POST ->
                let header = generateAuthorizationHeaderForAccessToken target meth consumerInfo requestInfo pinCode
                wc.Headers.Add ("Authorization", header)
                wc.AsyncUploadString url meth ""
        return result |> fromKeyValue
    } |> Async.RunSynchronously

let getAccessTokenByGet target consumerInfo requestInfo pinCode = getAccessToken target GET consumerInfo requestInfo pinCode
let getAccessTokenByPost target consumerInfo requestInfo pinCode = getAccessToken target POST consumerInfo requestInfo pinCode
