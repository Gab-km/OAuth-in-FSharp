=====
OAuth
=====

1 はじめに
----------
OAuth はデスクトップやWebアプリケーションから、シンプルで標準的な方法によるAPI認証を許可する、オープンなプロトコルの1つです。

2 使い方
--------
OAuth による認証が必要となるAPIを使いたい、そしてあなたのアプリケーションがF#で書かれている/書かれる予定であるとき、このライブラリを参照に追加しましょう。

この OAuth ライブラリは以下のリストに示すような構造となっている：

OAuth.Utilities
    OAuth に依存しないユーティリティ関数群

OAuth.Types
    このライブラリ用の型

OAuth.Core.Base
    OAuth に依存するユーティリティ関数群

OAuth.Core.Authentication
    Authenticationヘッダーを構築するための関数群

OAuth.API
    OAuth APIを使うための関数群

3 例
----

::

 (*
 このサンプルはTwitter APIを経由してアクセストークンとアクセス秘密鍵を取得します。
 与えられたパラメータ ― コンシューマーキーとコンシューマー秘密鍵 ― は偽の値です。
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

 // 'maybe' はMaybeモナド用のMaybeBuilderクラスのインスタンスである。
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

4 ライセンス
------------
Copyright 2011, Gab_km
 (blog: http://blog.livedoor.jp/gab_km/ , Twitter: @gab_km)

Apache License Version 2.0（「本ライセンス」）に基づいてライセンスされます。あなたがこのファイルを使用するためには、本ライセンスに従わなければなりません。本ライセンスのコピーは下記の場所から入手できます。

    http://www.apache.org/licenses/LICENSE-2.0

適用される法律または書面での同意によって命じられない限り、本ライセンスに基づいて頒布されるソフトウェアは、明示黙示を問わず、いかなる保証も条件もなしに「現状のまま」頒布されます。本ライセンスでの権利と制限を規定した文言については、本ライセンスを参照してください。
