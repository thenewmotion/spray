package spray.routing.authentication

import com.typesafe.config.{ ConfigException, Config }
import scala.concurrent.{ Future, ExecutionContext }
import spray.caching.{ LruCache, Cache }
import spray.routing.Route

case class OAuthAuthorizationCode(code: String)

case class OAuthAccessToken(token: String)

case class OAuthIdentity(subject: String, firstName: Option[String] = None, lastName: Option[String] = None) extends AuthenticatedIdentityContext { // and maybe some others.
  def uniqueId = subject
  def username = subject
}

/**
 * For OAuth authentication to a IdP.
 * This trait contains the interactive part that is different per IdP.
 */
trait OAuthTransformer {

  /* login url as needed to logon to the OAuth IdP in question */
  def loginUrl: String

  /* supply the route that is called by the authentication service to provide a token or access code */
  def callBackRoute(pathName: String): Route

  /* exchange a code to an accessToken */
  def accessToken(code: OAuthAuthorizationCode): Option[OAuthAccessToken]

  /* exchange a accessToken for a Identity */
  def userContext(accessToken: OAuthAccessToken): Option[OAuthIdentity]

}

/**
 */
object OAuthValidator {

  def apply[T <: AuthenticatedIdentityContext](f: OAuthValidator[T]) = f

  /**
   * Creates a OAuthValidator that uses .....
   */
  def fromConfig[T <: AuthenticatedIdentityContext](config: Config)(createUser: OAuthAccessToken ⇒ T): OAuthValidator[T] = {
    tokenOption ⇒
      Future.successful {
        tokenOption.flatMap { token ⇒
          try {
            val foundIdentity = createUser(token)
            Some(foundIdentity)
          } catch {
            case _: ConfigException ⇒ None
          }
        }
      }
  }

  /**
   * Creates a wrapper around an OAuthValidator providing authentication lookup caching using the given cache.
   * Note that you need to manually add a dependency to the spray-caching module in order to be able to use this method.
   */
  def cached[T <: AuthenticatedIdentityContext](inner: OAuthValidator[T], cache: Cache[Option[T]] = LruCache[Option[T]]())(implicit ec: ExecutionContext): OAuthValidator[T] = {
    tokenOption ⇒
      cache(tokenOption) {
        inner(tokenOption)
      }
  }

}

