FROM registry.k8s.io/kube-apiserver:v1.33.0 AS builder
ARG BASE=alpine:3.19
FROM ${BASE}
RUN adduser -D app
USER app
COPY --from=builder /usr/local/bin/kube-apiserver /usr/local/bin/kube-apiserver
CMD ["kube-apiserver", "--anonymous-auth=false"]
