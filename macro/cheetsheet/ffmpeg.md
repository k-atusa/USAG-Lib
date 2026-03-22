# ffmpeg usage

```bash
ffmpeg [global option] [input option] -i [input] [output option] [output]
```

trim/cut
```bash
ffmpeg -ss 00:01:30 -to 00:02:45 -i input.mp4 -c copy output.mp4
ffmpeg -ss 00:00:15 -i input.mp3 -t 30 -c copy output.mp3
```

merge media with same codec (require list file)
```bash
# requires file list text
file 'part1.mp4'
file 'part2.mp4'
file 'part3.mp4'

ffmpeg -f concat -safe 0 -i list.txt -c copy output.mp4
```

video to audio
```bash
ffmpeg -i input.mp4 -vn -c:a copy output.m4a
ffmpeg -i input.mp4 -vn -c:a libmp3lame -q:a 2 output.mp3
```

audio to video
```bash
ffmpeg -loop 1 -i image.png -i audio.mp3 -c:v libx264 -tune stillimage -c:a copy -shortest output.mp4
```

video re-encoding
```bash
ffmpeg -i input.mkv -c:v libx264 -preset medium -crf 23 -c:a aac output.mp4
ffmpeg -i input.mkv -c:v libx264 -b:v 2500k -maxrate 2500k -bufsize 5000k -c:a aac -b:a 128k output.mp4
```

| Format | CPU | NVIDIA (NVENC) | Intel (QSV) | AMD (AMF) | Apple |
| :--- | :--- | :--- | :--- | :--- | :--- |
| H.264 (AVC) | libx264 | h264_nvenc | h264_qsv | h264_amf | h264_videotoolbox |
| H.265 (HEVC) | libx265 | hevc_nvenc | hevc_qsv | hevc_amf | hevc_videotoolbox |
| AV1 | libsvtav1 | av1_nvenc | av1_qsv | av1_amf | av1_videotoolbox |

| Format | encoder |
| :--- | :--- |
| AAC | aac |
| MP3 | libmp3lame |
| Opus | libopus |
| FLAC | flac |
| Copy | copy |

video framerate/scale
```bash
ffmpeg -i input.mp4 -vf scale=1280:720 -r 30 -c:a copy output.mp4
ffmpeg -i input.mp4 -vf scale=1280:-2 -fpsmax 30 -c:a copy output.mp4
```

| Name | Scale |
| :--- | :--- |
| 8K | scale=7680:4320 |
| 4K | scale=3840:2160 |
| QHD (2K) | scale=2560:1440 |
| FHD (1080p) | scale=1920:1080 |
| HD (720p) | scale=1280:720 |
| SD (480p) | scale=854:480 |
| 360p | scale=640:360 |
