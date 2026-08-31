# Multi-stage build for the decision-plane service.
#
# Build context is the REPO ROOT (see deploy/docker-compose.yml) so this image can
# see both the service module and the in-repo contracts module that authorize-svc
# binds via a local `replace` in go.mod.
FROM golang:1.23-alpine AS build
WORKDIR /src

# Cache deps first: manifests + the local replace target (contracts module).
COPY services/authorize-svc/go.mod services/authorize-svc/go.sum* ./services/authorize-svc/
COPY contracts/gen/go/ ./contracts/gen/go/
WORKDIR /src/services/authorize-svc
RUN go mod download || true

# Now the sources.
WORKDIR /src
COPY services/authorize-svc/ ./services/authorize-svc/
COPY contracts/ ./contracts/
WORKDIR /src/services/authorize-svc
RUN go mod tidy

# Stamp build info via ldflags.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/authorize-svc ./cmd/authorize-svc

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/authorize-svc /authorize-svc
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/authorize-svc"]
