namespace OAuth

module API =
    open System.Text
    open OAuth.Types
    open OAuth.Utilities
    open OAuth.Base
    open OAuth.ExtendedWebClient

    let getRequestToken encode targetUrl httpMethod consumerInfo =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (targetUrl)
            let meth = getHttpMethodString httpMethod
            let encoder = urlEncode encode
            let! result =
                match httpMethod with
                | GET ->
                    let header = generateAuthorizationHeaderForRequestToken encoder targetUrl meth consumerInfo
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    let header = generateAuthorizationHeaderForRequestToken encoder targetUrl meth consumerInfo
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let getRequestTokenByGet encode target consumerInfo = getRequestToken encode target GET consumerInfo
    let getRequestTokenByPost encode target consumerInfo = getRequestToken encode target POST consumerInfo

    let getAccessToken encode target httpMethod consumerInfo requestInfo pinCode =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (target)
            let meth = getHttpMethodString httpMethod
            let encoder = urlEncode encode
            let! result =
                match httpMethod with
                | GET ->
                    let header = generateAuthorizationHeaderForAccessToken encoder target meth consumerInfo requestInfo pinCode
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    let header = generateAuthorizationHeaderForAccessToken encoder target meth consumerInfo requestInfo pinCode
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let getAccessTokenByGet encode target consumerInfo requestInfo pinCode = getAccessToken encode target GET consumerInfo requestInfo pinCode
    let getAccessTokenByPost encode target consumerInfo requestInfo pinCode = getAccessToken encode target POST consumerInfo requestInfo pinCode

    let useWebService encode target httpMethod consumerInfo accessInfo =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (target)
            let meth = getHttpMethodString httpMethod
            let encoder = urlEncode encode
            let! result =
                match httpMethod with
                | GET ->
                    let header = generateAuthorizationHeaderForWebService encoder target meth consumerInfo accessInfo
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    let header = generateAuthorizationHeaderForWebService encoder target meth consumerInfo accessInfo
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let useWebServiceByGet encode target consumerInfo accessInfo = useWebService encode target GET consumerInfo accessInfo
    let useWebServiceByPost encode target consumerInfo accessInfo = useWebService encode target POST consumerInfo accessInfo

    let useWebServiceWithData encode target httpMethod consumerInfo accessInfo data =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (target)
            let meth = getHttpMethodString httpMethod
            let encoder = urlEncode encode
            let! result =
                match httpMethod with
                | GET ->
                    let header = generateAuthorizationHeaderForWebServiceWithData encoder target meth consumerInfo accessInfo data
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    let header = generateAuthorizationHeaderForWebServiceWithData encoder target meth consumerInfo accessInfo data
                    wc.Headers.Add ("Authorization", header)
                    let param = System.Collections.Specialized.NameValueCollection()
                    param.Add ("status", OAuth.Utilities.urlEncode encode data)
                    wc.QueryString <- param
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously
