# Native VM test adapter; no upstream source or consensus patches here.
# Builder is produced from the pinned octra-foundry/docker/octra-node target.
ARG NATIVE_BUILDER=octra-private-admin-builder
FROM ${NATIVE_BUILDER}
COPY --chown=opam:opam scripts/private-admin/native-driver.ml test/private_admin_driver.ml
RUN printf '\n(executable (name private_admin_driver) (modules private_admin_driver) (libraries octra_vm octra_core yojson base64 zarith lwt.unix))\n' >> test/dune \
 && opam exec -- dune build --profile release test/private_admin_driver.exe
ENV OCTRA_PVAC_VERIFY_WORKER=/home/opam/build/_build/default/bin/octra_pvac_worker.exe
ENTRYPOINT ["/home/opam/build/_build/default/test/private_admin_driver.exe"]
CMD ["/vpn/program/main-v5.aml", "/vpn/program/private-admin-factory.aml"]
