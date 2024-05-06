package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type FileType int64

const (
	Video FileType = iota
	Image
)

var (
	imageRegex = regexp.MustCompile("(?i)(gif|png|jpg|jpeg|webp|gif|jfif)")
	videoRegex = regexp.MustCompile("(?i)(h264|h265|vp8|vp9)")
)

type FFConfig struct {
	ffmpegPath  string
	ffprobePath string
}

type ProcessedFile struct {
	thumbnail string
	format    FileType
	duration  time.Duration
}

type fileInfo struct {
	Streams []stream `json:"streams"`
}

type stream struct {
	CodecName      string `json:"codec_name"`
	CodecType      string `json:"codec_type"`
	CodecTagString string `json:"codec_tag_string"`
	Width          int    `json:"width,omitempty"`
	Height         int    `json:"height,omitempty"`
	PixFmt         string `json:"pix_fmt,omitempty"`
	Duration       cTime  `json:"duration"`
	Tags           tags   `json:"tags"`
}

type tags struct {
	Language string     `json:"language"`
	Duration vPDuration `json:"DURATION"`
}

type cTime struct {
	time.Duration
}

type vPDuration struct {
	time.Duration
}

func (t *vPDuration) UnmarshalJSON(data []byte) error {
	if string(data) == "null" || string(data) == `""` {
		return nil
	}
	t1, err := time.Parse("03:04:05.000000000", strings.ReplaceAll(string(data), `"`, ""))
	if err != nil {
		return err
	}
	d, err := time.ParseDuration(t1.Format("15h04m05s"))
	if err != nil {
		return err
	}
	*t = vPDuration{
		Duration: d,
	}
	return nil
}

func (t *cTime) UnmarshalJSON(data []byte) error {
	if string(data) == "null" || string(data) == `""` {
		return nil
	}
	d, err := time.ParseDuration(fmt.Sprintf("%vs", strings.ReplaceAll(string(data), `"`, "")))
	if err != nil {
		return err
	}
	*t = cTime{
		Duration: d,
	}
	return nil
}

func CheckVideo(ffprobe, path string) (fileInfo, error) {
	var info fileInfo
	c := exec.Command(ffprobe, "-v", "quiet", "-print_format", "json", "-show_streams", path)

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	c.Stdout = stdout
	c.Stderr = stderr
	e := c.Run()
	if e != nil {
		fmt.Println(stderr.String())
		fmt.Println(stdout.String())
		return info, fmt.Errorf("ffprobe failed at %v", path)
	}

	json.Unmarshal(stdout.Bytes(), &info)
	for _, v := range info.Streams {
		if v.CodecType == "video" {
			if v.CodecName == "vp9" || v.CodecName == "vp8" {
				info.Streams[0].Duration = cTime{v.Tags.Duration.Duration}
			}
			return info, nil
		}
	}
	return info, fmt.Errorf("no video stream in file %v", path)
}

func getThumbnail(ffmpeg, seek, path string) (string, error) {
	c := exec.Command(ffmpeg,
		"-ss", seek,
		"-i", path,
		"-frames:v", "1",
		"-vf", "scale=w=200:h=200:force_original_aspect_ratio=decrease",
		"-y", "-loglevel", "0", "-hide_banner",
		"-f", "image2pipe", "-")
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	c.Stdout = stdout
	c.Stderr = stderr
	err := c.Run()
	if err != nil {
		return "", fmt.Errorf("%v\tstdout: %v", err, stderr.String())
	}

	b64 := base64.RawStdEncoding.EncodeToString(stdout.Bytes())
	return fmt.Sprintf("data:image/jpeg;base64,%v", b64), nil
}

func MakeThumbnail(conf FFConfig, path string) (ProcessedFile, error) {
	p := ProcessedFile{}
	info, err := getFileInfo(conf, path)
	if err != nil {
		return p, err
	}
	if videoRegex.MatchString(info.Streams[0].CodecName) {
		p.format = Video
		p.duration = info.Streams[0].Duration.Duration

		// TODO: заменить на thumbnail filter
		if p.duration.Seconds() < 2 {
			p.thumbnail, err = getThumbnail(conf.ffmpegPath, "00:00:00.00", path)
		} else {
			p.thumbnail, err = getThumbnail(conf.ffmpegPath, "00:00:02.00", path)
		}
		if err != nil {
			return p, err
		}
		return p, nil
	}
	if imageRegex.MatchString(info.Streams[0].CodecName) {
		p.format = Image
		p.duration = 0
		p.thumbnail, err = getThumbnail(conf.ffmpegPath, "00:00:00.00", path)
		if err != nil {
			return p, err
		}
		return p, nil
	}
	return p, fmt.Errorf("file neither video nor image, skipping")
}

func getFileInfo(conf FFConfig, path string) (fileInfo, error) {
	var info fileInfo
	c := exec.Command(conf.ffprobePath, "-v", "quiet", "-print_format", "json", "-show_streams", path)
	// c := exec.Command(ffprobe, "-print_format", "json", "-show_streams", path)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	c.Stdout = stdout
	c.Stderr = stderr
	e := c.Run()
	if e != nil {
		fmt.Println(path)
		fmt.Println(stderr.String())
		fmt.Println(stdout.String())
		return info, fmt.Errorf("ffprobe failed at %v", path)
	}

	json.Unmarshal(stdout.Bytes(), &info)
	for _, v := range info.Streams {
		if v.CodecType == "video" {
			if v.CodecName == "vp9" || v.CodecName == "vp8" {
				info.Streams[0].Duration = cTime{v.Tags.Duration.Duration}
			}
			return info, nil
		}
	}
	return info, fmt.Errorf("no video stream in file %v", path)
}
