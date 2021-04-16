# Spring Boot OAuth server via LDAP login
This project is a sample authorization server that uses an LDAP as a source for authorization. It uses [Spring's experimental authorization server](https://github.com/spring-projects-experimental/spring-authorization-server) along with Spring Security's LDAP integration.


## Setup
The project includes the authorization server, a static webapp and the LDAP startup config file (`ldif`) to easily test the authorization server. You can use the included `docker-compose.yml` to test it locally (you will need `mvn` and `docker` installed on your host machine, check `Makefile` for available commands).

Running `make up` will setup the docker environment with the following ports exported:
- `:8081` is the web application, you can use this to test the PKCE authorization grant.
- `:9000` is the authorization server. It contains the login page and the OAuth2 endpoints (i.e. `http://localhost:9000/.well-known/openid-configuration`)
- `:1389` is the port to connect to the LDAP database.

