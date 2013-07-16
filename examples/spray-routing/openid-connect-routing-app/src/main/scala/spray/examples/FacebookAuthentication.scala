package spray.examples

import spray.client.pipelining._
import spray.http._
import spray.util._
import javax.net.ssl.SSLContext
import akka.actor.ActorSystem
import spray.routing.authentication._
import scala.concurrent.ExecutionContext
import spray.json._
import spray.httpx.SprayJsonSupport
import spray.routing.authentication.OAuthAccessToken
import spray.http.OAuth2BearerToken
import scala.Some
import spray.http.HttpResponse
import spray.routing.authentication.OAuthIdentity
import spray.routing.authentication.OAuthAuthorizationCode
import spray.http.Uri.Query
import spray.routing.directives.RespondWithDirectives._
import spray.routing.authentication.OAuthAccessToken
import spray.http.OAuth2BearerToken
import scala.Some
import spray.http.HttpResponse
import spray.routing.authentication.OAuthIdentity
import spray.routing.authentication.OAuthAuthorizationCode
import spray.http.MediaTypes._
import spray.routing.authentication.OAuthAccessToken
import spray.http.OAuth2BearerToken
import scala.Some
import spray.http.HttpResponse
import spray.routing.authentication.OAuthIdentity
import spray.routing.authentication.OAuthAuthorizationCode


/**
 * Simple implementation of the Google OAuth authentication mechanisms.
 * NOTE: THIS IS A SAMPLE ONLY, IT DOES NOT STORE OR CACHE THE TOKENS IN ANY WAY,
 * NEITHER IS THE SECURITY STATE RANDOMIZED OR SECURE.
 * IT DOES NOT RENEW TOKENS NOR VALIDATE THE LIFECYCLE OF TOKENS
 *
 * In Order to use this sample, you need to register your application at facebook
 * and obtain a client ID and clientSecret.
 * See: https://developers.facebook.com/docs/facebook-login/login-flow-for-web-no-jssdk/ for more information
 *
 * e.g. Use this for your own good, implement proper security and storage of tokens.
 *
 * @param oauthCallbackUrl Callback URI that is used for google to send authorization response
 * @param system  implicit found actor system
 * @param log implicit found log system
 */
class FacebookAuthentication(oauthCallbackUrl: Uri)(implicit system: ActorSystem, log: LoggingContext) extends OAuthTransformer {
  // response by the facebook call to return an identity
  //{"id":"1055486847","name":"Olger Warnier","first_name":"Olger","last_name":"Warnier","link":"http:\/\/www.facebook.com\/owarnier","username":"owarnier","gender":"male","email":"olger\u0040spectare.nl","timezone":2,"locale":"nl_NL","verified":true,"updated_time":"2013-06-13T18:46:40+0000"}

  case class OAuthIdentityResponse(id: String, name: String, first_name: String, last_name: String, link: String, username: String, gender: String, email: String, timezone: Int, locale: String, verified: Boolean, updated_time: String)

  object OAuthClientJsonProtocol extends DefaultJsonProtocol {
    implicit val oAuthIdentityResponseFormat = jsonFormat12(OAuthIdentityResponse)
  }

  import ExecutionContext.Implicits.global
  import OAuthClientJsonProtocol._
  import SprayJsonSupport._


  // facebook
  private val authServer = Uri("https://www.facebook.com/dialog/oauth")
  private val tokenServer = Uri("https://graph.facebook.com/oauth/access_token")
  private val clientId = "YOUR_CLIENT_ID_HERE"
  private val clientSecret = "YOUR_CLIENT_SECRET_HERE"
  private val identityUrl = "https://graph.facebook.com/me"
  //https://graph.facebook.com/me?access_token=

  private implicit val mySSLContext: SSLContext = {
    val context = SSLContext.getDefault
    context
  }

  def loginUrl =
    s"""
     |$authServer?
     |client_id=$clientId&
     |response_type=code&
     |state=AAAAAAA&
     |redirect_uri=$oauthCallbackUrl&
     |scope=email
    """.stripMargin
  //     |scope=openid%20email&


  def accessToken(code: OAuthAuthorizationCode): Option[OAuthAccessToken] = {

    val pipeline = logRequest(log) ~> sendReceive ~> logResponse(log)

    val postData = FormData(Map("code" -> code.code, "client_id" -> clientId, "client_secret" -> clientSecret,
      "redirect_uri" -> (oauthCallbackUrl.toString), "grant_type" -> "authorization_code"))

    val responseFuture = pipeline { Post(tokenServer, postData) }
    val result = responseFuture.await
    //HttpResponse(200 OK,HttpEntity(text/plain; charset=UTF-8,access_token=CAAC80FcIc0kBAKNa3gxnpdjZALB9pHBgU3KsMYtoOQmhbLDH3tIbW06WuLnQt7IzJpLlj0aSJw3Nh6aAXGQj9o5ySqhsPxz04MAlZBCpLGVZCNhfYZAVmM6xjJ44FkR3cQt7q3blYcYQbN0hcBH7&expires=5184000),List(Content-Length: 178, Connection: keep-alive, Date: Tue, 16 Jul 2013 18:08:52 GMT, X-FB-Debug: Vc/QMj9oV26mt/z/t0YwfnxjmBdAdfHGgAUKliQ/NXM=, X-FB-Rev: 876422, Pragma: no-cache, Expires: Sat, 01 Jan 2000 00:00:00 GMT, Content-Type: text/plain; charset=UTF-8, Cache-Control: private, no-cache, no-store, must-revalidate, Access-Control-Allow-Origin: *),HTTP/1.1)
    result match {
      case HttpResponse(StatusCodes.OK, entity, _, _) => {
        log.debug("OK result = " + entity.asString)
        Query(entity.asString).get("access_token").map(t => OAuthAccessToken(t)).orElse(None)
      }
      case _ => {
        log.debug("result = " + result)
        None
      }
    }
  }


  def userContext(accessToken: OAuthAccessToken): Option[OAuthIdentity] = {
    //HttpResponse(200 OK,HttpEntity(text/javascript; charset=UTF-8,{"id":"1055486847","name":"Olger Warnier","first_name":"Olger","last_name":"Warnier","link":"http:\/\/www.facebook.com\/owarnier","username":"owarnier","gender":"male","email":"olger\u0040spectare.nl","timezone":2,"locale":"nl_NL","verified":true,"updated_time":"2013-06-13T18:46:40+0000"}),List(Content-Length: 289, Connection: keep-alive, Date: Tue, 16 Jul 2013 18:20:08 GMT, X-FB-Debug: dx9tSglmLZWjUZW2GDb0Xie4PgEj9UlKYzf9rTZSku0=, X-FB-Rev: 876422, Pragma: no-cache, Last-Modified: 2013-06-13T18:46:40+0000, Expires: Sat, 01 Jan 2000 00:00:00 GMT, ETag: "d2dceb50681613af79192b7af99477fef2896240", Content-Type: text/javascript; charset=UTF-8, Cache-Control: private, no-cache, no-store, must-revalidate, Access-Control-Allow-Origin: *),HTTP/1.1)
    val pipeline = logRequest(log) ~> sendReceive ~> logResponse(log)

    val responseFuture = pipeline {
      addCredentials(OAuth2BearerToken(accessToken.token)) { Get(identityUrl) }
    }

    val result = responseFuture.await
    result match {
      case HttpResponse(StatusCodes.OK, entity, _, _) => {
        log.debug("OK result = " + entity.asString)
        val fbId = entity.asString.asJson.convertTo[OAuthIdentityResponse]
        Some(OAuthIdentity(fbId.id, Some(fbId.first_name), Some(fbId.last_name)))
      }
      case _ => {
        log.debug("result = " + result)
        None
      }
    }
  }

  def callBackRoute(pathName: String): _root_.spray.routing.Route = {
    import spray.routing.directives.BasicDirectives._
    import spray.routing.directives.DebuggingDirectives._
    import spray.routing.directives.PathDirectives._
    import spray.routing.directives.ParameterDirectives._
    import spray.routing.directives.RouteDirectives._
    import spray.http.MediaTypes._
    import spray.routing.directives.RespondWithDirectives._

    pathPrefix(pathName) {
      logRequest("oauthCallBack") {
        extract(_.request) {
          found =>
            log.debug("callback:" + found.toString)

            parameters('code.as[String] ?, 'state.as[String] ?, 'session_state.as[String] ?) {
              (code: Option[String], state: Option[String], sessionState: Option[String]) =>
                val accessToken = code.map(cbCode => this.accessToken(OAuthAuthorizationCode(cbCode))).orElse(None)

                accessToken match {
                  case Some(res) => {
                    log.debug("access token:" + res)
                    val userInfo = this.userContext(res.get)
                    log.debug("user Info:" + userInfo)
                    respondWithMediaType(`text/html`) {
                      complete {
                        <html>
                          <p>Bearer token: {res}</p>
                          <p>User Info: {userInfo}</p>
                        </html>
                      }
                    }
                  }
                  case _ => {
                    respondWithMediaType(`text/html`) {
                      complete {
                        <html>
                          <p>No accessToken found</p>
                        </html>
                      }
                    }
                  }
                }
            }
        }
      }
    }
  }
}
