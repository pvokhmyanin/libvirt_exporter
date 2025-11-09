OUT_DIR := build
APP_NAME := libvirt_exporter


.PHONY: help
help: ## Show this help
	@sed -ne '/@sed/!s/## //p' $(MAKEFILE_LIST)

.PHONY: binary
binary: ## Build the binary and export it to host filesystem
	rm -rf $(OUT_DIR)
	mkdir $(OUT_DIR)
	docker build -t ${APP_NAME} .
	@CTID=$$(docker create ${APP_NAME}:latest) && \
	docker cp $${CTID}:/${APP_NAME} ${OUT_DIR}/ && \
	docker rm $${CTID}
	@echo "\n${APP_NAME} built and copied to ./${OUT_DIR}/ directory"

.PHONY: image
image: ## Build docker image
	docker build -t ${APP_NAME} .

.PHONY: run
run: ## Run the built container
	docker build -t ${APP_NAME} .
	docker run -d -it -p 9177:9177 -v /var/run/libvirt/libvirt-sock:/var/run/libvirt/libvirt-sock --name $(APP_NAME) $(APP_NAME):latest

.PHONY: clean
clean: ## Remove output directory
	rm -rf $(OUT_DIR)
