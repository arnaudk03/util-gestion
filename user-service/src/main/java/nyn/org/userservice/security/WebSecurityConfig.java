package nyn.org.userservice.security;


import lombok.AllArgsConstructor;
import nyn.org.userservice.security.jwt.AuthEntryPointJwt;
import nyn.org.userservice.security.jwt.AuthTokenFilter;
import nyn.org.userservice.security.services.UserDetailsServiceImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;


@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class WebSecurityConfig  {

    UserDetailsServiceImpl userDetailsService;

    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
                // Use customizer for CORS
                .cors(CorsConfigurer::disable)  // Disable CORS (or configure it)
                // Disable CSRF
                .csrf(AbstractHttpConfigurer::disable)
                // Handle unauthorized access attempts
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling.authenticationEntryPoint(unauthorizedHandler)
                )
                // Stateless session management
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Authorize requests
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/api/auth/**").permitAll()  // Public routes for auth
                                .requestMatchers("/api/test/**").permitAll()  // Another public route
                                .anyRequest().authenticated()  // All other routes require authentication
                );

        // Add the JWT filter before UsernamePasswordAuthenticationFilter
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
