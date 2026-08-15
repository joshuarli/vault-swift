NAME      := vault
BUILD_DIR := .build/release
PREFIX    ?= $(HOME)/usr

# Self-signed code-signing identity, created automatically by the
# codesign-identity target on first use.
SIGN_ID ?= Vault Signing

install: build codesign-identity
	codesign --sign "$(SIGN_ID)" --force --timestamp=none $(BUILD_DIR)/$(NAME)
	mkdir -p $(PREFIX)/bin
	cp $(BUILD_DIR)/$(NAME) $(PREFIX)/bin/$(NAME)

build:
	swift build -c release

codesign-identity:
	@if security find-identity -p codesigning 2>/dev/null | grep -q "$(SIGN_ID)"; then \
		echo "code-signing identity '$(SIGN_ID)' already present"; \
	else \
		tmp=$$(mktemp -d); \
		trap 'rm -rf "$$tmp"' EXIT; \
		/usr/bin/openssl req -x509 -newkey rsa:2048 \
			-keyout "$$tmp/vault-key.pem" -out "$$tmp/vault-cert.pem" \
			-days 3650 -nodes \
			-subj "/CN=$(SIGN_ID)" \
			-addext "basicConstraints=critical,CA:false" \
			-addext "keyUsage=critical,digitalSignature" \
			-addext "extendedKeyUsage=codeSigning" && \
		/usr/bin/openssl pkcs12 -export \
			-out "$$tmp/vault-cert.p12" \
			-inkey "$$tmp/vault-key.pem" -in "$$tmp/vault-cert.pem" \
			-passout pass:vault && \
		security import "$$tmp/vault-cert.p12" \
			-k "$$HOME/Library/Keychains/login.keychain-db" \
			-P vault -T /usr/bin/codesign -A && \
		echo "created code-signing identity '$(SIGN_ID)'"; \
	fi

test:
	swift test

.PHONY: install build codesign-identity test
