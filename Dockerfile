# Both images must be digest-pinned by the release pipeline.
# The build image must include Go, a C compiler, libpq headers and libpq.
# The runtime image must include libpq.
ARG GO_BUILD_IMAGE
ARG RUNTIME_IMAGE
FROM ${GO_BUILD_IMAGE} AS build
WORKDIR /src
COPY . .
RUN VERSION="$(cat VERSION)" && test -n "$VERSION" && test -f /usr/include/postgresql/libpq-fe.h && \
    CGO_ENABLED=1 go test ./... && \
    CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -buildid= -X platform.4so.io/factory/internal/buildinfo.Version=$VERSION" -o /out/platform-api ./cmd/platform-api

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/platform-api /platform-api
EXPOSE 8080
ENV PLATFORM_FACTORY_LISTEN=0.0.0.0:8080
USER nonroot:nonroot
ENTRYPOINT ["/platform-api"]
