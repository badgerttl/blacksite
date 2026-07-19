.PHONY: init up up-local down pull build status logs urls config

init:
	./blacksite init
up:
	./blacksite up
up-local:
	./blacksite up --local-llm
down:
	./blacksite down
pull:
	./blacksite pull
build:
	./blacksite build
status:
	./blacksite status
logs:
	./blacksite logs
urls:
	./blacksite urls
config:
	./blacksite config

