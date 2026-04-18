FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/relay /relay
USER nonroot:nonroot
EXPOSE 8443 9000
ENTRYPOINT ["/relay"]
