# yt-dlp usage

yt-dlp requires ffmpeg to process media
```bash
yt-dlp "URL"
yt-dlp -F "URL"
```

set scale limit / mp4 convert
```bash
# 1080 720 480 360

yt-dlp -f "bestvideo[height<=1080]+bestaudio/best" -S "ext:mp4:m4a" "URL"
```

download audio
```bash
# --embed-thumbnail includes thumbnail to audio

yt-dlp -x --audio-format mp3 --embed-thumbnail --audio-quality 320K "URL"
```

download playlist
```bash
# --playlist-items 1,3,5-10

yt-dlp -o "%(playlist_index)02d_%(title)s.%(ext)s" "URL"
```

download with subtitles
```bash
yt-dlp --write-subs --sub-langs "ko" "URL"
```

download via chrome login
```bash
# need to be logined to youtube with chrome

yt-dlp --cookies-from-browser chrome "URL"
```
