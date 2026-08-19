.PHONY: init up up-local up-hoppscotch-proxy down pull build status logs urls config doctor

init:
	./blacksite init
up:
	./blacksite up
up-local:
	./blacksite up --local-llm
up-hoppscotch-proxy:
	./blacksite up --hoppscotch-proxy
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
doctor:
	./blacksite doctor
