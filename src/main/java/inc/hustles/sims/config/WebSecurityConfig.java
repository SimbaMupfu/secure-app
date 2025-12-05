package inc.hustles.sims.config;

import inc.hustles.sims.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    public WebSecurityConfig(CustomUserDetailsService userDetailsService){
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(authorise ->
                authorise.requestMatchers("/register", "/login").permitAll()
                        .requestMatchers("/greet").authenticated()
                        .anyRequest().permitAll())
                .formLogin(form ->
                        form.loginPage("/login")
                                .defaultSuccessUrl("/greet")
                                .permitAll())
                .logout(logout ->
                        logout.permitAll()
                );
        return http.build();
    }
}
