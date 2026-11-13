# Brand reference logos

This folder holds the reference logo images used by
`phishing/brand_detector.py`.

**No logos are included in this project.** Logos are copyrighted by their
owners, so you must add your own reference images manually.

## How to add a reference logo

1. Save a clear image of the logo as PNG, JPG or JPEG.
2. Copy it into this folder.
3. Name the file after the brand, e.g.:

```
phishing/brand_references/google.png
phishing/brand_references/microsoft.png
phishing/brand_references/amazon.png
phishing/brand_references/paypal.png
```

The file name becomes the brand name (`google.png` -> "google").
Other names work too (e.g. `netflix.png`, `apple.jpg`).

## Tips for better results

- Use a square or nearly square image (about 200-500 pixels per side).
- Prefer logos on a plain background.
- Use one logo per brand.
- If the uploaded logo includes large surrounding text or a full
  screenshot, similarity scores will be lower.

## Notes

- Reference files are read at request time, so you can add or remove
  logos without restarting the server.
- Corrupt or unsupported files are skipped safely.
- If this folder contains no readable images, the API returns
  `"Unknown"` instead of a match.
