FROM registry.access.redhat.com/ubi10/ubi:10.2 AS builder

# Install the builder dependencies
RUN dnf -y install \
    --setopt=install_weak_deps=false \
    --setopt=tsflags=nodocs \
    --setopt=deltarpm=0 \
    --allowerasing \
    python3.12-pip \
    python3.12-devel \
    git \
    gcc \
    make \
    && dnf clean all \
    && mkdir -p /export/wheels

# Copy the project source code
COPY . /src/
WORKDIR /src

# Generate the wheels, including the OCI extra (oras) needed by `fath-cuan index create --attach-to`
RUN pip3.12 wheel --wheel-dir=/export/wheels '.[oci]'


# Build the final image using task-runner which includes oras and other Tekton tooling
FROM quay.io/konflux-ci/task-runner:1.5.0

LABEL \
    name="fath-cuan" \
    maintainer="Lightwell Developers" \
    licence="Apache-2.0"

# Copy the wheels from the builder stage
COPY --from=builder /export/ /

USER 0

ARG RH_IT_CERT

# Install dependencies
RUN echo "${RH_IT_CERT}" | base64 -d > /etc/pki/ca-trust/source/anchors/Current-IT-Root-CAs.pem \
    && update-ca-trust \
    && microdnf install -y \
        python3.12-pip \
        jq \
    # for CVEs in base image
    && microdnf update -y \
    && microdnf clean all \
    && pip3.12 install --no-cache-dir --no-deps /wheels/*.whl \
    && rm -rf /wheels

# Set the internal certificates (OSIDB enrichment talks to internal Red Hat endpoints)
ENV REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
ENV SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt

# Run the CLI
ENTRYPOINT ["fath-cuan"]
