FROM golang:alpine AS build
WORKDIR /src
ADD . /src
RUN apk add --no-cache --update ca-certificates git
RUN go build -o gcp-iap-auth

# final stage
FROM alpine
COPY --from=build /src/gcp-iap-auth /bin

EXPOSE 80 443
ENTRYPOINT ["/bin/gcp-iap-auth"]
