package shop.yesaladin.security.provider;

import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import shop.yesaladin.common.dto.ResponseDto;
import shop.yesaladin.security.dto.AuthorizationMetaResponseDto;
import shop.yesaladin.security.token.JwtAuthenticationToken;

@RequiredArgsConstructor
public class JwtTokenAuthenticationProvider implements AuthenticationProvider {

    private final RestTemplate restTemplate;
    private final String authUrl;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        String token = (String) authentication.getCredentials();

        try {
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.add("Authorization", token);

            RequestEntity<Void> requestEntity = new RequestEntity<>(
                    httpHeaders,
                    HttpMethod.GET,
                    URI.create(authUrl + "/authorizations")
            );

            ResponseEntity<ResponseDto<AuthorizationMetaResponseDto>> authorizationMetaEntity = restTemplate.exchange(
                    requestEntity,
                    new ParameterizedTypeReference<>() {
                    }
            );

            AuthorizationMetaResponseDto authorizationMeta = authorizationMetaEntity.getBody()
                    .getData();

            return JwtAuthenticationToken.authenticated(
                    token,
                    authorizationMeta.getLoginId(),
                    authorizationMeta.getRoles()
            );
        } catch (RestClientException e) {
            throw new BadCredentialsException("invalid token : " + token);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(JwtAuthenticationToken.class);
    }
}
