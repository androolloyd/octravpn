ARG RUST_IMAGE
ARG NATIVE_BUILDER
FROM ${RUST_IMAGE} AS rust
FROM ${NATIVE_BUILDER} AS native_build
WORKDIR /mixed-native
COPY upstream/ ./
COPY native/ ./mixed_validator_host/
COPY expected.json /mixed-expected.json
USER root
RUN chown -R opam:opam /mixed-native
USER opam
RUN python3 -c 'import hashlib,json,pathlib; x=json.load(open("/mixed-expected.json")); assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h for p,h in x["native_sources"].items())'
RUN python3 -c 'import hashlib,json,pathlib,shutil; x=json.load(open("/mixed-expected.json")); assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h for p,h in x["native_archive_inputs"].items()); a=x["builder_generated_artifacts"][0]; p=pathlib.Path(a["path"]); assert p.stat().st_size==a["size"] and hashlib.sha256(p.read_bytes()).hexdigest()==a["sha256"]; q=pathlib.Path(a["destination"]); q.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,q)'
RUN opam exec -- dune build -j 4 ./mixed_validator_host/main.exe
RUN python3 -c 'import hashlib,json,pathlib; x=json.load(open("/mixed-expected.json")); assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h for p,h in x["native_archive_inputs"].items()); assert all(hashlib.sha256(pathlib.Path(a["destination"]).read_bytes()).hexdigest()==a["sha256"] for a in x["builder_generated_artifacts"])'
RUN python3 -c 'import hashlib,json,pathlib; x=json.load(open("/mixed-expected.json")); assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h for p,h in x["native_sources"].items())'

FROM ${NATIVE_BUILDER}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3-cryptography procps && rm -rf /var/lib/apt/lists/*
COPY --from=rust /usr/local/bin/octra /usr/local/bin/octra
COPY --from=rust /usr/local/bin/octra-node /usr/local/bin/octra-node
COPY --from=rust /usr/local/bin/octra-single-fixture /usr/local/bin/octra-single-fixture
COPY --from=rust /usr/local/bin/octravpn /usr/local/bin/octravpn
COPY --from=rust /usr/local/bin/octravpn-node /usr/local/bin/octravpn-node
COPY --from=rust /usr/local/bin/octravpn-private-admin /usr/local/bin/octravpn-private-admin
COPY --from=rust /usr/local/share/native-source.json /usr/local/share/native-source.json
COPY --from=native_build /mixed-native/_build/default/mixed_validator_host/main.exe /usr/local/bin/octra-native-mixed-host
COPY runner/ /mixed-fixture/
COPY expected.json /mixed-fixture/expected.json
WORKDIR /mixed-fixture
ENTRYPOINT ["python3", "-u", "/mixed-fixture/run.py", "--inside"]
CMD []
