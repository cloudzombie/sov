SOV Station — desktop wallet + node for SOV (XUS)

The app runs a SOV node in-process and opens on MAINNET (the live network,
genesis cb0272ff, launched midnight July 4 2026). Create or import a wallet,
hold and send XUS (transparent or shielded), and optionally mine. Switch to the
Testnet sandbox from the network tab at the top if you want to experiment with
nothing at stake.

SOV is a young network — live, but new and not yet independently audited. Hold
funds accordingly. Your recovery phrase is the ONLY backup of your keys; write it
down and keep it offline.

macOS (Apple Silicon M1/M2/M3 + Intel): the app is open-source and ad-hoc signed but
NOT Apple-notarized (notarization requires a paid Apple Developer account). macOS may say
it is "damaged" or from an unidentified developer. To open it, drag SOV Station to
Applications, then run this ONCE in Terminal:

    xattr -cr "/Applications/SOV Station.app"

and double-click it normally. That clears the download-quarantine flag — the app is not
actually damaged. (Right-click -> Open also works on some macOS versions.)
Windows: unsigned — SmartScreen → More info → Run anyway.

Explorer: https://sovxus.org   ·   Site: https://www.sovxus.com
