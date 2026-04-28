## Plan: Mosh-style Display Sync

**Two independent phases.** Phase 1 requires no server-side vt100 and can ship first. Phase 2 extends it to full state sync.

---

### Phase 1 — Clean reconnect via client-side rendering

The problem: scrollback replay sends 64 KiB of raw PTY history including all past cursor movements, producing visible noise. The fix: bracket the replay with new signals so the client can absorb it silently and emit a single clean repaint.

**Steps**

1. **Add `ScrollbackStart` / `ScrollbackEnd` to `EncryptedFrame`** — `libmoshpit/src/frames/encframe.rs`
   Two new unit variants, ids 5 and 6.

2. **Wrap scrollback replay** — `moshpits/src/runtime.rs`, `resolve_session()` around the `sb_data.chunks(...)` loop
   Send `ScrollbackStart` before, `ScrollbackEnd` after.

3. **Silent-absorb + clean-render in `client_frame_loop`** — `libmoshpit/src/udp/reader.rs`
   - Add `renderer: Arc<Mutex<Renderer>>` parameter back
   - Add `scrollback_mode: bool` flag
   - `ScrollbackStart` → set flag, stop sending raw bytes to stdout; feed bytes into emulator only
   - `ScrollbackEnd` → `renderer.invalidate()` + `renderer.render(emu.screen(), &[], None)` → single stdout write; clear flag

4. **Restore `Renderer` in `run_udp_session` and `spawn_resize_handler`** — `moshpit/src/runtime.rs`
   Recreate `renderer` Arc, pass to reader; `spawn_resize_handler` calls `renderer.set_size()` on SIGWINCH again.

5. **Add new variants to server reader catch-all** — these only flow server→client; add to `EncryptedFrame::Nak(_) | EncryptedFrame::Keepalive` arms in `server_frame_loop`.

---

### Phase 2 — Full server-side state sync (*depends on Phase 1*)

The server tracks screen state with vt100. On reconnect, instead of scrollback replay, it sends a single `ScreenState` frame (current screen contents). Periodic ticks allow the client to receive compressed screen diffs even during normal use.

**Steps** *(1–2 parallel; 3–5 parallel; 7 depends on 3+4; 8 depends on Phase 1 step 3)*

1. Add `vt100 = "0.15.2"` to `moshpits/Cargo.toml`
2. Add `ScreenState(Vec<u8>)` to `EncryptedFrame` (id 7) — `libmoshpit/src/frames/encframe.rs`
3. Add `server_emulator: Arc<Mutex<vt100::Parser>>` to `SessionRecord` — `moshpits/src/session.rs`
4. Feed PTY chunks into server emulator in `spawn_pty_reader()` — `moshpits/src/runtime.rs`
5. Resize server emulator when `TerminalMessage::Resize` is processed in the PTY input loop — `moshpits/src/runtime.rs`
6. Spawn a ~50ms periodic task that sends `EncryptedFrame::ScreenState(screen.contents_formatted())` — dirty-flag or u64 hash guards against sending unchanged screens *(parallel with 4+5)*
7. Replace scrollback replay in `resolve_session()` with a single `ScreenState` frame *(depends on 3, 4)*
8. Handle `ScreenState` in `client_frame_loop` — feed payload into a temporary `vt100::Parser`, call `renderer.render(tmp.screen(), &[], None)`, send result to stdout *(depends on Phase 1 step 3)*
9. Add `ScreenState` to server reader catch-all arm

---

### Key design decisions

- **`contents_formatted()` as wire format** — no custom serialization needed; client deserializes by feeding bytes into a fresh `vt100::Parser` and reading `.screen()`
- **Scrollback ring kept** in Phase 2 for debugging and for clients that don't yet understand `ScreenState`
- **Windows `mps`** is fine — `vt100` is pure Rust; ConPTY quirks may cause minor screen-state inaccuracies but nothing breaking

### Verification

- After Phase 1 — reconnect produces a single clean repaint with no noise
- After Phase 2 — reconnect from a different network yields an instant correct screen with no replay delay
- Both phases: `cargo clippy --all-targets -- -Dwarnings` and `cargo doc -p libmoshpit` pass
