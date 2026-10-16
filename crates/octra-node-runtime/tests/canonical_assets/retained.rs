use super::*;

#[tokio::test]
async fn retained_public_assets_prove_legacy_and_paged_paths_without_restoring_old_trees() {
    for paged in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut state = initial();
        if paged {
            for index in 0..300 {
                state
                    .set(&[format!("unrelated-{index}").as_bytes()], vec![0])
                    .unwrap();
            }
        }
        for variant in ["ok", "revoked", "expired", "sealed", "hash", "inflated"] {
            let mut meta = asset(&mut state, "MiXeD", &format!("/{variant}"), b"old");
            match variant {
                "revoked" => policy(
                    &mut state,
                    b"MiXeD",
                    &format!(
                        "slot_policy:{}:revoked",
                        String::from_utf8_lossy(&meta.path_key)
                    ),
                    "true",
                ),
                "expired" => meta.expire_after_epoch = Some(0),
                "sealed" => meta.body_mode = ResourceMode::Sealed,
                "hash" => meta.blob_hash = b"f".repeat(64),
                "inflated" => {
                    state
                        .set(
                            &[
                                b"circles",
                                b"MiXeD",
                                b"assets",
                                b"by_hash",
                                &meta.path_key,
                                b"body_b64",
                            ],
                            vec![b'A'; 8192],
                        )
                        .unwrap();
                }
                _ => (),
            }
            write_meta(&mut state, b"MiXeD", &meta);
        }
        let store = create(&dir.path().join("chain.db"), &state).await;
        let old = CanonicalAssets::capture(&store).await.unwrap().retained();
        let url = OctUrl::parse("oct://MiXeD/ok").unwrap();
        assert_eq!(&*old.resolve(&url).await.unwrap().bytes, b"old");
        for variant in ["revoked", "expired", "sealed", "hash", "inflated"] {
            assert!(
                old.resolve(&OctUrl::parse(&format!("oct://MiXeD/{variant}")).unwrap())
                    .await
                    .is_err(),
                "{variant}"
            );
        }
        assert!(matches!(
            old.resolve(&OctUrl::parse("oct://mixed/ok").unwrap()).await,
            Err(Error::NotFound)
        ));
        let (head, mut next) = store.snapshot().await.unwrap();
        next.begin().unwrap();
        next.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
        asset(&mut next, "MiXeD", "/ok", b"new");
        let expected_root =
            octra_node_runtime::canonical::execution_root(&head, 1, &next.snapshot(), &[]).unwrap();
        store
            .prepare(
                &head,
                AppliedEpoch {
                    epoch: 1,
                    state: next.snapshot(),
                    expected_root,
                    transactions: vec![],
                    certificate: b"trusted raw storage fixture".to_vec(),
                    date: 1,
                    message: vec![],
                },
            )
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let new = CanonicalAssets::capture(&store).await.unwrap().retained();
        assert_ne!(new.provenance(), old.provenance());
        assert_eq!(&*old.resolve(&url).await.unwrap().bytes, b"old");
        assert_eq!(&*new.resolve(&url).await.unwrap().bytes, b"new");
        store.close().await;
    }
}
