SOV Station — desktop wallet + node for SOV (XUS)

The app runs a SOV node in-process and opens on MAINNET (the live network,
genesis cb0272ff, launched midnight July 4 2026). Create or import a wallet,
hold and send XUS (transparent or shielded), and optionally mine. Switch to the
Testnet sandbox from the network tab at the top if you want to experiment with
nothing at stake.

SOV is a young network — live, but new and not yet independently audited. Hold
funds accordingly. Your recovery phrase is the ONLY backup of your keys; write it
down and keep it offline.

macOS (Apple Silicon, including M3 and later): this download is native ARM64,
with an M1-compatible CPU baseline and macOS 11.0 deployment target. Use the
macOS version supported by your Mac; this ARM64 package is not an Intel build.
The app renders with Metal and is open-source and ad-hoc signed but
NOT Apple-notarized (notarization requires a paid Apple Developer account). macOS may say
it is "damaged" or from an unidentified developer. To open it, drag SOV Station to
Applications, then run this ONCE in Terminal:

    xattr -cr "/Applications/SOV Station.app"

and double-click it normally. That clears the download-quarantine flag.
(Right-click -> Open also works on some macOS versions.) If it still does not
open, keep the diagnostic logs in ~/.sov-station/logs; do not delete your wallet
or node data. From Terminal, the installed app can check its native RandomX path:

    "/Applications/SOV Station.app/Contents/MacOS/sov-station" --self-test-platform
Windows: unsigned — SmartScreen → More info → Run anyway.

Peer/bootstrap address: 158.101.18.90:9645 (P2P, not the RPC port).
Upgrade miners and relays together to protocol 3; 0.2.14 uses protocol 2.
Keep the existing wallet and node data. Mainnet reset is disabled in 0.2.16.
Pool-v2 replacement readiness starts at height 27,648; earliest activation is
28,224, requiring 90% miner signaling. Existing notes remain visible throughout.

Read-only native diagnostics:
    sov-station diagnostics 127.0.0.1:8645
    sov-rpcd --verify-history chain-spec.json blocks.log

Explorer: https://sovxus.org   ·   Site: https://www.sovxus.com
