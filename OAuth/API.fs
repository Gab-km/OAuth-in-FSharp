namespace OAuth

module API =
    open System.Text
    open System.Collections.Specialized
    open OAuth.Types
    open OAuth.Utilities
    open OAuth.Base
    open OAuth.ExtendedWebClient

    let asyncAPIBase requirement header parameter =
        async {
            let (Requirement (encoding, targetUrl, httpMethod)) = requirement
            let wc = new System.Net.WebClient ()
            let url = System.Uri (targetUrl)
            let meth = getHttpMethodString httpMethod
            let! result =
                wc.Headers.Add ("Authorization", header)
                let rec setPostParameter keyValue (param : NameValueCollection) =
                    match keyValue with
                    | kv::kvs ->
                        let encoder = urlEncode encoding
                        let (KeyValue (key, value)) = kv
                        param.Add (encoder key, encoder value)
                        setPostParameter kvs param
                    | _ -> param
                let param = setPostParameter parameter (NameValueCollection())
                wc.QueryString <- param
                match httpMethod with
                | GET -> wc.AsyncDownloadString url
                | POST -> wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let getRequestToken requirement consumerInfo parameter =
        let header = generateAuthorizationHeaderForRequestToken requirement consumerInfo
        asyncAPIBase requirement header parameter

    let getAccessToken requirement consumerInfo requestInfo pinCode parameter =
        let header = generateAuthorizationHeaderForAccessToken requirement consumerInfo requestInfo pinCode
        asyncAPIBase requirement header parameter

    let useWebService requirement consumerInfo accessInfo parameter =
        let header = generateAuthorizationHeaderForWebService requirement consumerInfo accessInfo parameter
        asyncAPIBase requirement header parameter
