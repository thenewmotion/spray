package spray.routing

import spray.routing.authentication._
import spray.http._
import HttpHeaders._
import spray.http.HttpHeaders.Authorization
import spray.http.OAuth2BearerToken
import scala.concurrent.Future
import spray.util.LoggingContext

/**
 */
class OpenIDConnectAuthenticatorSpec extends RoutingSpec {

  val dontAuth = OAuthValidator[OAuthIdentity](_ ⇒ Future.successful(None))

  val doAuth = OAuthValidator[OAuthIdentity] { tokenOption ⇒
    Future.successful(Some(OAuthIdentity("alice@email.id")))
  }

  val oAuthComm = new OAuthTransformer {
    /* exchange a code to an accessToken */
    def accessToken(code: OAuthAuthorizationCode): Option[OAuthAccessToken] = Some(OAuthAccessToken("accessCode"))

    /* exchange a accessToken for a Identity */
    def userContext(accessToken: OAuthAccessToken): Option[OAuthIdentity] = Some(OAuthIdentity("plaintextID"))

    def callBackRoute(pathName: String): _root_.spray.routing.Route = { path("callback") { complete("OK") } }

    /* login url as needed to logon to the OAuth IdP in question */
    def loginUrl: String = "https://loginURL"
  }

  "the 'authenticate(OAuth())' directive" should {
    "reject requests without Authorization header with an AuthenticationRequiredRejection" in {
      Get() ~> {
        authenticate(OAuth(dontAuth, oAuthComm, "Realm")) { echoComplete }
      } ~> check { rejection === AuthenticationRequiredRejection("Bearer", "Realm", Map("error" -> "invalid_token", "error_description" -> "The access token expired")) }
    }
    "reject unauthenticated requests with Authorization header with an AuthorizationFailedRejection" in {
      Get() ~> Authorization(OAuth2BearerToken("BTOKEN")) ~> {
        authenticate(OAuth(dontAuth, oAuthComm, "Realm")) { echoComplete }
      } ~> check { rejection === AuthenticationFailedRejection("Bearer", "Realm", Map("error" -> "invalid_token", "error_description" -> "The access token expired")) }
    }
    "extract the object representing the user identity created by successful authentication" in {
      Get() ~> Authorization(OAuth2BearerToken("BTOKEN")) ~> {
        authenticate(OAuth(doAuth, oAuthComm, "Realm")) { echoComplete }
      } ~> check { entityAs[String] === "OAuthIdentity(alice@email.id,None,None)" }
    }
    "properly handle exceptions thrown in its inner route" in {
      object TestException extends spray.util.SingletonException
      Get() ~> Authorization(OAuth2BearerToken("BTOKEN")) ~> {
        handleExceptions(ExceptionHandler.default) {
          authenticate(OAuth(doAuth, oAuthComm, "Realm")) { _ ⇒ throw TestException }
        }
      } ~> check { status === StatusCodes.InternalServerError }
    }
  }

}
