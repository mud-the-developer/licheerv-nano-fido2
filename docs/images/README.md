# Token2 screenshot review

Source: operator-provided screenshot of https://www.token2.com/tools/fido2-demo. Added after the previous operator-guide commit, which did not contain the image. The original local screenshot is preserved outside the public repository.

## What is visible

The demo displays both **Registration completed successfully** and **Login completed successfully**. The agent visually reviewed the provided image and the metadata-stripped public copy. No PIN, passphrase, credential ID, public-key dump, account name, browser profile, device serial or operational network address is visible. No pixel redaction was needed.

This is evidence of the operator's displayed browser result. Browser/version, exact options, timing and authenticator identity are not visible. It does not independently bind the screenshot to a particular device, replay the browser operation, prove certification or establish a broad compatibility matrix. The operator identified the experiment as the Nano trial; separate physical USB tests are documented in TEST-STATUS.md.

## Public asset

- File: `token2-demo-success.png`
- SHA256: `fbe238e193c6294967c1924f571a07f1f4c6b99e98a89dc6a748f6e8d667b82f`
- PNG chunks retained: IHDR, IDAT, IEND.
- Ancillary chunks removed: gAMA, pHYs, sRGB. No pixel data was changed.
- The publication checker allows only this exact path/digest after visual review. A new or changed image needs a new review; arbitrary binary files remain rejected.

Token2 owns its demo UI. This operator-supplied capture is included solely as test evidence and is not a Token2 endorsement or certification of the project.
