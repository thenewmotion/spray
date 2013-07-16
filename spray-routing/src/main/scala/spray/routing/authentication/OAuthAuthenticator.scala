package spray.routing.authentication

import scala.concurrent.ExecutionContext
import spray.routing.RoutingSettings
import spray.http.{ OAuth2BearerToken, HttpCredentials }
import com.typesafe.config.Config
import spray.routing.RequestContext
import scala.Some

/**
 * The OpenID Connect Authenticator implements OpenID Connect resource server checking.
 */
class OAuthAuthenticator[U <: AuthenticatedIdentityContext](val realm: String, transformer: OAuthTransformer, val oidConnectValidator: OAuthValidator[U])(implicit val executionContext: ExecutionContext)
    extends HttpAuthenticator[U] {

  def scheme = "Bearer"
  def params(ctx: RequestContext) = Map("error" -> "invalid_token", "error_description" -> "The access token expired")

  def authenticate(credentials: Option[HttpCredentials], ctx: RequestContext) = {
    oidConnectValidator {
      credentials.flatMap {
        case OAuth2BearerToken(token) ⇒ Some(OAuthAccessToken(token))
        case _                        ⇒ None
      }
    }
  }

}

/**
 * Helper to create easy configurations in the Route.
 * Like:
 * path("protected") {
 *       authenticate(OAuth("Realm", oauthComm)) { user =>
 *
 * where oauthComm is an instance of the implemented OAuthTransformer trait
 */
object OAuth {

  def apply(transformer: OAuthTransformer)(implicit settings: RoutingSettings, ec: ExecutionContext): OAuthAuthenticator[OAuthIdentity] =
    apply("Secured Resource", transformer)

  def apply(realm: String, transformer: OAuthTransformer)(implicit settings: RoutingSettings, ec: ExecutionContext): OAuthAuthenticator[OAuthIdentity] =
    apply(realm, transformer, accessToken ⇒ transformer.userContext(accessToken).get)

  def apply[T <: AuthenticatedIdentityContext](realm: String, transformer: OAuthTransformer, createUser: OAuthAccessToken ⇒ T)(implicit settings: RoutingSettings, ec: ExecutionContext): OAuthAuthenticator[T] =
    apply(realm, settings.users, transformer, createUser)

  def apply[T <: AuthenticatedIdentityContext](realm: String, config: Config, transformer: OAuthTransformer, createUser: OAuthAccessToken ⇒ T)(implicit ec: ExecutionContext): OAuthAuthenticator[T] =
    apply(OAuthValidator.fromConfig(config)(createUser), transformer, realm)

  def apply[T <: AuthenticatedIdentityContext](validator: OAuthValidator[T], transformer: OAuthTransformer, realm: String)(implicit ec: ExecutionContext): OAuthAuthenticator[T] =
    new OAuthAuthenticator[T](realm, transformer, validator)
}
