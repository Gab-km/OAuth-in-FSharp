=====
OAuth
=====

1 Introduction
--------------
OAuth is one of the open protocols to allow API authentication in a simple and standard methods from desktop and web applications.

2 Usage
-------
When you want to use the API that needs authenticated by OAuth, and your application is/will be written in F#, then you add reference of this library.

This OAuth library is organized like the list below:

OAuth.Utilities
    the OAuth-independant utility functions

OAuth.Types
    the types for this library

OAuth.Core.Base
    the OAuth-dependant utility functions

OAuth.Core.Authentication
    the functions to build the Authentication header

OAuth.API
    the functions to use OAuth API

3 Examples
----------
 (*
 This sample is to get the access token and the access secret via Twitter API.
 Given parameters - the consumer key and the consumer secret - are just fake.
 *)

 open OAuth.Types
 open OAuth.Core.Base
 open OAuth.API

 let consumerInfo = { consumerKey="abcdefghijklmnopqrstuv";
                      consumerSecret="wxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab" }

 let requestTokenResponse = OAuth.API.getRequestToken
                             <| Requirement (System.Text.Encoding.ASCII,
                                             "https://api.twitter.com/oauth/request_token",
                                             GET)
                             <| consumerInfo
                             <| []

 System.Console.WriteLine requestTokenResponse

 System.Console.Write "Input your pin code. > "
 let pinCode = System.Console.ReadLine ()
 let reqList = fromParameter requestTokenResponse

 // 'maybe' is the instance of the MaybeBuilder class for the Maybe monad.
 let accessTokenResponse =
     maybe {
         let! requestToken = tryGetValue "oauth_token" reqList
         let! requestSecret = tryGetValue "oauth_token_secret" reqList

         return OAuth.API.getAccessToken
                 <| Requirement (System.Text.Encoding.ASCII,
                                 "https://api.twitter.com/oauth/access_token",
                                 GET)
                 <| consumerInfo
                 <| { requestToken=requestToken; requestSecret=requestSecret }
                 <| pinCode
                 <| []
     }

 System.Console.WriteLine accessTokenResponse

4 License
---------
Copyright 2011, Gab_km
 (blog: http://blog.livedoor.jp/gab_km/ , Twitter: @gab_km)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
