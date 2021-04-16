package eu.arima.config;

import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

	@Value("${spring.ldap.urls:ldap://localhost:1389}")
	private String ldapUrl;

	@Value("${spring.ldap.base:dc=arima,dc=eu}")
	private String baseDn;


	@Bean
	public UserDetailsService ldapUserDetails() throws Exception {
		String searchBase = "ou=people";
		String searchFilter = "(uid={0})";
		LdapUserSearch userSearch = new FilterBasedLdapUserSearch(searchBase, searchFilter, contextSource());
		return new LdapUserDetailsService(userSearch, ldapAuthoritiesPopulator());
/*
		return auth.ldapAuthentication()
			.contextSource(contextSource())
			.userSearchFilter("(uid={0})")
			.userSearchBase("ou=people")
			.ldapAuthoritiesPopulator(ldapAuthoritiesPopulator())
			.groupSearchFilter("(member={0})")
			.groupSearchBase("ou=groups")
			.passwordCompare()
				.passwordEncoder(new LdapShaPasswordEncoder())
				.passwordAttribute("userPassword")
				.and()
			.and()
		.build();*/
	}

	@Bean
	public PasswordEncoder ldapPassEncoder() {
		return new LdapShaPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
			.authorizeRequests()
				.antMatchers("/").permitAll()
				.anyRequest().authenticated()
				.and()
			.formLogin().permitAll().and()
			.logout().permitAll().logoutSuccessUrl("/").and()
			.build();
	}

	@Bean
	public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
		DefaultLdapAuthoritiesPopulator populi = new DefaultLdapAuthoritiesPopulator(contextSource(), "ou=groups") {

			private static final String ADMIN_ROLE = "ROLE_ADMIN";
			@Override
			public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
				Set<GrantedAuthority> groupMembershipRoles = super.getGroupMembershipRoles(userDn, username);

				boolean isMemberOfSpecificAdGroup = false;
				for (GrantedAuthority grantedAuthority : groupMembershipRoles) {

					if (ADMIN_ROLE.equals(grantedAuthority.toString())) {
						isMemberOfSpecificAdGroup = true;
						break;
					}
				}

				if (!isMemberOfSpecificAdGroup) {
					throw new BadCredentialsException("User must be a member of " + ADMIN_ROLE);
				}
				return groupMembershipRoles;
			}
		};

		return populi;
	}

	@Bean
	public DefaultSpringSecurityContextSource contextSource() {
		String ldapServer = this.ldapUrl;
		if (!ldapServer.endsWith("/")) ldapServer += "/";
		return new DefaultSpringSecurityContextSource(ldapServer + this.baseDn);
	}
	
}
