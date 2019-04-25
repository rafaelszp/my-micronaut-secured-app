package my.secured.app2.security;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.DefaultRolesFinder;
import io.micronaut.security.token.RolesFinder;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Requires(property = "spec.name", value = "customclaimsrolesparser")
@Replaces(DefaultRolesFinder.class)
@Singleton
public class MySecParser implements RolesFinder {

  private static final String REALM_ACCESS_KEY = "realm_access";
  private static final String ROLES_KEY = "roles";

  @Nonnull
  @Override
  public List<String> findInClaims(@Nonnull Claims claims) {
    List<String> roles = new ArrayList<>();
    if (claims.contains(REALM_ACCESS_KEY)) {
      if (claims.get(REALM_ACCESS_KEY) instanceof Map) {
        Map realAccessMap = (Map) claims.get(REALM_ACCESS_KEY);
        if ( realAccessMap.containsKey(ROLES_KEY)) {
          Object realAccess = realAccessMap.get(ROLES_KEY);
          if (realAccess != null) {
            if (realAccess instanceof Iterable) {
              for (Object o : ((Iterable) realAccess)) {
                roles.add(o.toString());
              }
            } else {
              roles.add(realAccess.toString());
            }
          }
        }
      }
    }
    return roles;
  }
}
