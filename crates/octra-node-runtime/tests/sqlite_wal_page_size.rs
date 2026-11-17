//! Regression for the vendored SQLite backport of upstream
//! `e5bf119821f25be1d7f10ef0a2edbe175289166e` (RUSTSEC-2026-0459 /
//! CVE-2026-119375): a WAL whose page size is smaller than the database's
//! must not leave the tail of a page buffer uninitialised.
//!
//! The node opens SQLite files it did not write when an operator adopts a
//! retained-state directory, so a crafted `canonical.sqlite` + `-wal` pair is
//! a real input. The test builds exactly that pair: a 4 KiB-page database
//! and a hand-written WAL with 512-byte pages that supplies one overflow
//! page. With a small page cache already cycled through 0xAA data, an
//! unpatched SQLite returns the recycled buffer's old contents after the
//! first 512 bytes; the patched one returns zeros.

use std::path::Path;

use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    Row,
};

const DB_PAGE: usize = 4096;
const WAL_PAGE: usize = 512;
/// Little-endian-checksum WAL magic (`0x377f0682`); see SQLite's `wal.c`.
const WAL_MAGIC: u32 = 0x377f_0682;
const WAL_VERSION: u32 = 3_007_000;
const SECRET: u8 = 0xAA;
const PAYLOAD: u8 = 0x5A;

/// SQLite's WAL checksum over `data` (a multiple of 8 bytes), continuing
/// from `seed`, reading words little-endian to match [`WAL_MAGIC`].
fn checksum(seed: (u32, u32), data: &[u8]) -> (u32, u32) {
    let (mut s0, mut s1) = seed;
    for pair in data.chunks_exact(8) {
        let x0 = u32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]);
        let x1 = u32::from_le_bytes([pair[4], pair[5], pair[6], pair[7]]);
        s0 = s0.wrapping_add(x0).wrapping_add(s1);
        s1 = s1.wrapping_add(x1).wrapping_add(s0);
    }
    (s0, s1)
}

/// A one-frame WAL with [`WAL_PAGE`]-byte pages that commits `page` as page
/// `number` of a database `database_pages` pages long.
fn crafted_wal(number: u32, page: &[u8], database_pages: u32) -> Vec<u8> {
    assert_eq!(page.len(), WAL_PAGE);
    let (salt1, salt2) = (0x0c7a_0001_u32, 0x0c7a_0002_u32);
    let mut wal = Vec::with_capacity(32 + 24 + WAL_PAGE);
    wal.extend_from_slice(&WAL_MAGIC.to_be_bytes());
    wal.extend_from_slice(&WAL_VERSION.to_be_bytes());
    wal.extend_from_slice(&u32::try_from(WAL_PAGE).unwrap().to_be_bytes());
    wal.extend_from_slice(&0_u32.to_be_bytes()); // checkpoint sequence
    wal.extend_from_slice(&salt1.to_be_bytes());
    wal.extend_from_slice(&salt2.to_be_bytes());
    let header = checksum((0, 0), &wal[..24]);
    wal.extend_from_slice(&header.0.to_be_bytes());
    wal.extend_from_slice(&header.1.to_be_bytes());

    let mut frame = Vec::with_capacity(24);
    frame.extend_from_slice(&number.to_be_bytes());
    frame.extend_from_slice(&database_pages.to_be_bytes()); // commit frame
    frame.extend_from_slice(&salt1.to_be_bytes());
    frame.extend_from_slice(&salt2.to_be_bytes());
    let sum = checksum(checksum(header, &frame[..8]), page);
    frame.extend_from_slice(&sum.0.to_be_bytes());
    frame.extend_from_slice(&sum.1.to_be_bytes());
    wal.extend_from_slice(&frame);
    wal.extend_from_slice(page);
    wal
}

/// Create the 4 KiB-page database and leave it cleanly checkpointed: one
/// row whose blob needs a single overflow page, plus enough 0xAA rows to
/// cycle a small page cache.
async fn build_database(path: &Path) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .page_size(u32::try_from(DB_PAGE).unwrap())
                .journal_mode(SqliteJournalMode::Wal),
        )
        .await
        .unwrap();
    sqlx::query("CREATE TABLE victim(id INTEGER PRIMARY KEY, x BLOB)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO victim VALUES (1, ?)")
        .bind(vec![PAYLOAD; 6000])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE secrets(id INTEGER PRIMARY KEY, y BLOB)")
        .execute(&pool)
        .await
        .unwrap();
    for _ in 0..96 {
        sqlx::query("INSERT INTO secrets(y) VALUES (?)")
            .bind(vec![SECRET; 3000])
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

/// The overflow page of the `victim` row: the only page that is entirely
/// payload after a zero "next overflow page" pointer.
fn overflow_page(database: &[u8]) -> u32 {
    let hit = database
        .chunks_exact(DB_PAGE)
        .position(|page| page[..4] == [0; 4] && page[4..].iter().all(|byte| *byte == PAYLOAD))
        .expect("victim overflow page");
    u32::try_from(hit).unwrap() + 1
}

#[tokio::test]
async fn smaller_wal_page_never_exposes_recycled_page_cache_memory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("canonical.sqlite");
    build_database(&path).await;

    let database = std::fs::read(&path).unwrap();
    assert_eq!(database.len() % DB_PAGE, 0);
    let pages = u32::try_from(database.len() / DB_PAGE).unwrap();
    let target = overflow_page(&database);
    let start = (usize::try_from(target).unwrap() - 1) * DB_PAGE;

    // The crafted sibling: same page number, only the first 512 bytes.
    let wal = crafted_wal(target, &database[start..start + WAL_PAGE], pages);
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    std::fs::write(format!("{}-wal", path.display()), wal).unwrap();

    // Eight cached pages, one connection: reading `secrets` leaves every
    // buffer the cache can recycle full of 0xAA.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .pragma("cache_size", "8"),
        )
        .await
        .unwrap();
    let primed: i64 = sqlx::query("SELECT count(*) FROM secrets WHERE hex(y) LIKE 'AAAA%'")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(primed, 96);

    let blob: Vec<u8> = sqlx::query("SELECT x FROM victim WHERE id = 1")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    pool.close().await;

    // Everything the WAL frame really supplied is payload; everything past
    // its 512 bytes must be zero — not whatever the buffer held before.
    assert_eq!(blob.len(), 6000);
    let supplied = blob.iter().take_while(|byte| **byte == PAYLOAD).count();
    let tail = &blob[supplied..];
    assert_eq!(
        tail.len(),
        DB_PAGE - WAL_PAGE,
        "the WAL frame covers 512 of the overflow page's 4096 bytes"
    );
    let leaked = tail.iter().filter(|byte| **byte != 0).count();
    assert_eq!(
        leaked, 0,
        "{leaked} bytes of recycled page-cache memory reached a query result"
    );
}
