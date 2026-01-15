import Icons

t = Icons.Icons()
with open("zip.png", "wb") as f:
    f.write(t.zip_png())
with open("zip.webp", "wb") as f:
    f.write(t.zip_webp())
with open("aes.png", "wb") as f:
    f.write(t.aes_png())
with open("aes.webp", "wb") as f:
    f.write(t.aes_webp())
with open("cloud.png", "wb") as f:
    f.write(t.cloud_png())
with open("cloud.webp", "wb") as f:
    f.write(t.cloud_webp())
