namespace OAuth

module API =
    open System.Text
    open OAuth.Types
    open OAuth.Base
    open OAuth.ExtendedWebClient

    let getRequestToken targetUrl httpMethod consumerInfo =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (targetUrl)
            let meth = getHttpMethodString httpMethod
            let encode = Encoding.UTF8
            let! result =
                match httpMethod with
                | GET ->
                    let header = generateAuthorizationHeaderForRequestToken encode targetUrl meth consumerInfo
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    let header = generateAuthorizationHeaderForRequestToken encode targetUrl meth consumerInfo
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let getRequestTokenByGet target consumerInfo = getRequestToken target GET consumerInfo
    let getRequestTokenByPost target consumerInfo = getRequestToken target POST consumerInfo

    let getAccessToken target httpMethod consumerInfo requestInfo pinCode =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (target)
            let meth = getHttpMethodString httpMethod
            let encode = Encoding.UTF8
            let! result =
                match httpMethod with
                | GET ->
                    let header = generateAuthorizationHeaderForAccessToken encode target meth consumerInfo requestInfo pinCode
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    let header = generateAuthorizationHeaderForAccessToken encode target meth consumerInfo requestInfo pinCode
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let getAccessTokenByGet target consumerInfo requestInfo pinCode = getAccessToken target GET consumerInfo requestInfo pinCode
    let getAccessTokenByPost target consumerInfo requestInfo pinCode = getAccessToken target POST consumerInfo requestInfo pinCode

    let useWebService target httpMethod consumerInfo accessInfo =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (target)
            let meth = getHttpMethodString httpMethod
            let encode = Encoding.UTF8
            let! result =
                match httpMethod with
                | GET ->
                    let header = generateAuthorizationHeaderForWebService encode target meth consumerInfo accessInfo
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    let header = generateAuthorizationHeaderForWebService encode target meth consumerInfo accessInfo
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    let useWebServiceByGet target consumerInfo accessInfo = useWebService target GET consumerInfo accessInfo
    let useWebServiceByPost target consumerInfo accessInfo = useWebService target POST consumerInfo accessInfo

    let useWebServiceWithData target httpMethod consumerInfo accessInfo data =
        async {
            let wc = new System.Net.WebClient ()
            let url = System.Uri (target)
            let meth = getHttpMethodString httpMethod
            let encode = Encoding.UTF8
            let! result =
                match httpMethod with
                | GET ->
                    let header = generateAuthorizationHeaderForWebServiceWithData encode target meth consumerInfo accessInfo data
                    wc.Headers.Add ("Authorization", header)
                    wc.AsyncDownloadString url
                | POST ->
                    let header = generateAuthorizationHeaderForWebServiceWithData encode target meth consumerInfo accessInfo data
                    wc.Headers.Add ("Authorization", header)
                    let param = System.Collections.Specialized.NameValueCollection()
                    param.Add ("status", OAuth.Utilities.urlEncode encode data)
                    wc.QueryString <- param
                    wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously
