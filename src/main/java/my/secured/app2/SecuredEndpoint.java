package my.secured.app2;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.reactivex.Single;

@Requires(property = "spec.name", value = "customclaimsrolesparser")
@Controller("/")
public class SecuredEndpoint {

  @Secured({SecurityRule.IS_AUTHENTICATED})
  @Get("secured")
  public Single<Authentication> getSecret(Authentication auth){
    return Single.just(auth);
  }

  @Secured("demo")
  @Get("cr5")
  public Single<Authentication> getSecretCr5(Authentication auth){
    return Single.just(auth);
  }

  @Secured({SecurityRule.IS_ANONYMOUS})
  @Get("/insecured")
  public Single<String> hello(){
    return Single.just("{\"response\":\"I am not a secured endpoint\"}");
  }

}
