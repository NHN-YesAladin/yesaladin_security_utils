package shop.yesaladin.security.token;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtAuthenticationToken implements Authentication {

    private boolean isAuthenticated;
    private final String token;
    private final String loginId;
    private final List<String> authorities;

    public static JwtAuthenticationToken unAuthenticated(String token) {
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(
                token,
                null,
                null
        );
        jwtAuthenticationToken.setAuthenticated(false);
        return jwtAuthenticationToken;
    }

    public static JwtAuthenticationToken authenticated(
            String token, String loginId, List<String> authorities
    ) {
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(
                token,
                loginId,
                authorities
        );
        jwtAuthenticationToken.setAuthenticated(true);
        return jwtAuthenticationToken;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities == null ? null : authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getDetails() {
        return new User(loginId, null, getAuthorities());
    }

    @Override
    public Object getPrincipal() {
        return loginId;
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return loginId;
    }
}
