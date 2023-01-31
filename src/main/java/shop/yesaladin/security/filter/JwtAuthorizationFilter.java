package shop.yesaladin.security.filter;

import java.io.IOException;
import java.util.Objects;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.filter.OncePerRequestFilter;
import shop.yesaladin.security.token.JwtAuthenticationToken;

@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String token = request.getHeader("Authorization");
        if (Objects.isNull(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        JwtAuthenticationToken authenticationToken = JwtAuthenticationToken.unAuthenticated(token);

        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        SecurityContextImpl securityContext = new SecurityContextImpl(authenticate);

        SecurityContextHolder.setContext(securityContext);

        filterChain.doFilter(request, response);
    }
}
