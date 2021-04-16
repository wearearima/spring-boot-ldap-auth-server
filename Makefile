
up:
	cd auth-server && mvn package
	docker-compose up --build -d

down:
	docker-compose down